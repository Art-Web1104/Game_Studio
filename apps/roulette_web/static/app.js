/*
 * R4-UI-0006 · internal prototype roulette client.
 *
 * What this file is allowed to do
 * -------------------------------
 * Collect an intent, send it to the loopback server, and render whatever comes back. That
 * is the whole contract. There is no rule engine here, no payout arithmetic, no balance
 * arithmetic and no source of randomness of any kind: the pocket, whether a bet won, the
 * amount returned and the resulting balance are read out of the server's response and
 * displayed verbatim. The wheel is decoration wrapped around a number the server chose --
 * it is rotated *to* the result, it never produces one.
 *
 * Request identifiers are generated here, but only as an idempotency key. They are a
 * monotonic counter over a per-load token, never an outcome, and deliberately not random:
 * a retry must reuse the identifier of the attempt it is retrying, otherwise a spin whose
 * response was lost would be charged twice. Every action therefore keeps its identifier
 * until the server has answered for it, and the server replays the original result for a
 * duplicate rather than drawing again.
 *
 * The board, the pocket colours and the selection sizes all come from `/api/state`, so the
 * client cannot offer a bet the authoritative table does not know about.
 */

(function () {
  "use strict";

  // ── presentation constants ──────────────────────────────────────────────────────────

  /*
   * The physical pocket sequence of a European single-zero wheel. This is layout, in the
   * same sense that the order of keys on a keyboard is layout: it decides where a number
   * is *drawn*, and has no part in deciding which number wins. If it disagreed with the
   * server's pocket list the client would fall back to that list instead.
   */
  var WHEEL_LAYOUT = [
    0, 32, 15, 19, 4, 21, 2, 25, 17, 34, 6, 27, 13, 36, 11, 30, 8, 23, 10, 5, 24, 16, 33, 1,
    20, 14, 31, 9, 22, 18, 29, 7, 28, 12, 35, 3, 26,
  ];

  /* Bet types whose `selections` value is a group index rather than a pocket number. Used
     only to decide where a chip mark is drawn; the server owns what the index means. */
  var INDEX_SELECTION_TYPES = ["dozen", "column"];

  var TYPE_LABELS = {
    straight: "스트레이트",
    split: "스플릿",
    street: "스트리트",
    corner: "코너",
    six_line: "식스라인",
    dozen: "더즌",
    column: "컬럼",
    red: "빨강",
    black: "검정",
    odd: "홀수",
    even: "짝수",
    low: "1–18",
    high: "19–36",
  };

  var DOZEN_LABELS = { 1: "1st 12 (1–12)", 2: "2nd 12 (13–24)", 3: "3rd 12 (25–36)" };
  var COLUMN_LABELS = { 1: "1열", 2: "2열", 3: "3열" };
  var COLOR_LABELS = { red: "빨강", black: "검정", green: "초록" };

  var PHASE_LABELS = {
    OPEN: "베팅 가능",
    LOCKED: "베팅 마감",
    SPINNING: "추첨 중",
    SETTLING: "정산 중",
    SETTLED: "정산 완료",
    VOIDED: "무효",
  };

  /* Server refusal codes get a sentence a player can act on. An unmapped code falls back
     to the server's own message, which is already written to be safe to display. */
  var ERROR_MESSAGES = {
    BET_INVALID: "이 조합은 규칙에 맞지 않습니다. 번호 조합을 다시 확인해 주세요.",
    INSUFFICIENT_CHIPS: "남은 가상 칩보다 큰 금액입니다. 칩 금액을 낮춰 주세요.",
    HOUSE_EXPOSURE_EXCEEDED: "테이블 한도를 넘는 베팅입니다. 금액을 낮춰 주세요.",
    BET_LIMIT_REACHED: "이번 라운드에 담을 수 있는 베팅 수를 넘었습니다.",
    NO_BETS: "먼저 베팅을 하나 이상 담아 주세요.",
    PHASE_DENIED: "지금 라운드 상태에서는 할 수 없는 동작입니다.",
    ROUND_IN_PROGRESS: "진행 중인 라운드가 끝난 뒤에 새 라운드를 열 수 있습니다.",
    TERMINAL_STATE: "이미 끝난 라운드입니다. 새 라운드를 열어 주세요.",
    REQUEST_ID_CONFLICT: "같은 요청 번호가 다른 내용으로 재사용됐습니다. 새 라운드를 열어 주세요.",
    REQUEST_ID_ALREADY_USED: "이미 처리된 요청 번호입니다. 새 라운드를 열어 주세요.",
    NETWORK: "서버에 연결하지 못했습니다. 서버가 켜져 있는지 확인한 뒤 다시 시도해 주세요.",
  };

  var SPIN_ANIMATION_MS = 4200;
  var SPIN_EXTRA_TURNS = 6;

  // ── element handles ─────────────────────────────────────────────────────────────────

  function $(id) {
    return document.getElementById(id);
  }

  var el = {
    tableId: $("table-id"),
    balance: $("balance-units"),
    reserved: $("reserved-units"),
    available: $("available-units"),
    rotor: $("wheel-rotor"),
    pocket: $("result-pocket"),
    pocketValue: $("result-pocket-value"),
    pocketLabel: $("result-pocket-label"),
    phase: $("round-phase"),
    roundId: $("round-id"),
    status: $("status"),
    announcer: $("announcer"),
    errorAlert: $("error-alert"),
    errorMessage: $("error-message"),
    retry: $("retry-button"),
    settlement: $("settlement"),
    settlementStake: $("settlement-stake"),
    settlementReturn: $("settlement-return"),
    settlementNet: $("settlement-net"),
    history: $("history-list"),
    board: $("board"),
    selectionHint: $("selection-hint"),
    draftList: $("draft-list"),
    draftCount: $("draft-count"),
    placedList: $("placed-list"),
    placedCount: $("placed-count"),
    slipTotal: $("slip-total"),
    serverNotice: $("server-notice"),
    clear: $("clear-button"),
    rebet: $("rebet-button"),
    spin: $("spin-button"),
    newRound: $("new-round-button"),
  };

  var ui = {
    server: null, // the last `/api/state` snapshot, untouched
    drafts: [], // bets composed locally, not yet accepted by the server
    selection: [], // pockets picked for the current inside bet
    betType: "straight",
    chip: 25,
    busy: false,
    lastBalance: null,
    lastRoundBets: [], // copied at settlement so 리베팅 has something to repeat
    wheelTurn: 0,
    wheelPockets: [],
    pendingIds: {}, // action -> request id held until the server answers
    retryAction: null,
    freshDraftIds: {},
  };

  var numberFormat = new Intl.NumberFormat("ko-KR");
  var reducedMotion =
    typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-reduced-motion: reduce)")
      : { matches: false };

  function prefersReducedMotion() {
    return Boolean(reducedMotion.matches);
  }

  // ── formatting helpers ──────────────────────────────────────────────────────────────

  function chips(units) {
    return numberFormat.format(units) + " 칩";
  }

  function signedChips(units) {
    return (units > 0 ? "+" : "") + chips(units);
  }

  function typeLabel(type) {
    return TYPE_LABELS[type] || type;
  }

  function betLabel(bet) {
    var selections = bet.selections || [];
    if (bet.type === "dozen") {
      return typeLabel(bet.type) + " · " + (DOZEN_LABELS[selections[0]] || selections[0]);
    }
    if (bet.type === "column") {
      return typeLabel(bet.type) + " · " + (COLUMN_LABELS[selections[0]] || selections[0]);
    }
    if (selections.length) {
      return typeLabel(bet.type) + " · " + selections.join(", ");
    }
    return typeLabel(bet.type);
  }

  function requiredSelections(type) {
    var counts = ui.server && ui.server.table ? ui.server.table.bet_selection_counts : null;
    if (!counts || !Object.prototype.hasOwnProperty.call(counts, type)) {
      return null;
    }
    return counts[type];
  }

  /* The payout ratio is shown, never applied: this reads the number the server published
     in its rules snapshot and puts it on screen. No stake is multiplied by it anywhere. */
  function payoutRatioLabel(type) {
    var table = ui.server && ui.server.table ? ui.server.table.payouts : null;
    if (!table || !Object.prototype.hasOwnProperty.call(table, type)) {
      return "";
    }
    return "배당 " + table[type] + " : 1";
  }

  function isIndexSelectionType(type) {
    return INDEX_SELECTION_TYPES.indexOf(type) !== -1;
  }

  /*
   * The colour of a pocket is a server value, never a client decision. `/api/state` publishes
   * `state.table.pocket_colors`, keyed by the pocket as a string, derived from the same rule
   * and the same function that colour a settled result -- so the board, the wheel and the
   * result can never disagree about what 32 is.
   *
   * The rules snapshot also carries `state.table.red_numbers`, and this client deliberately
   * never reads it. Turning that list into "red, black or green" here would put a second,
   * unversioned copy of a rule in the one place nobody audits, and the first thing to notice
   * the two copies had drifted apart would be a player. A pocket the server did not classify
   * is therefore left uncoloured rather than guessed at.
   */
  function pocketColor(colors, pocket) {
    if (!colors || !Object.prototype.hasOwnProperty.call(colors, String(pocket))) {
      return "none";
    }
    return colors[String(pocket)];
  }

  // ── request identifiers ─────────────────────────────────────────────────────────────

  /*
   * `REQUEST_ID_PATTERN` on the server is ^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$. The token is
   * the page load time in base 36 and the suffix is a counter, which is unique for this
   * single-player local table and -- unlike a random key -- reproducible enough to reason
   * about when reading an audit trail.
   */
  var sessionToken = Date.now().toString(36).toUpperCase();
  var requestCounter = 0;

  function newRequestId(kind) {
    requestCounter += 1;
    var suffix = String(requestCounter);
    while (suffix.length < 4) {
      suffix = "0" + suffix;
    }
    return "R4UI-" + sessionToken + "-" + kind + "-" + suffix;
  }

  /* Hold one identifier per action until it has been answered, so a retry is a replay of
     the same request rather than a second, different one. */
  function heldRequestId(action, kind) {
    if (!ui.pendingIds[action]) {
      ui.pendingIds[action] = newRequestId(kind);
    }
    return ui.pendingIds[action];
  }

  function releaseRequestId(action) {
    delete ui.pendingIds[action];
  }

  // ── transport ───────────────────────────────────────────────────────────────────────

  function ApiError(code, message, status) {
    this.name = "ApiError";
    this.code = code;
    this.message = message;
    this.status = status;
  }
  ApiError.prototype = Object.create(Error.prototype);
  ApiError.prototype.constructor = ApiError;

  function request(method, path, body) {
    var init = { method: method, headers: { Accept: "application/json" } };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return fetch(path, init).then(
      function (response) {
        return response.text().then(function (text) {
          var payload = null;
          try {
            payload = text ? JSON.parse(text) : null;
          } catch (parseError) {
            payload = null;
          }
          if (!response.ok) {
            var detail = payload && payload.error ? payload.error : {};
            throw new ApiError(
              detail.code || "HTTP_" + response.status,
              detail.message || "요청이 거절됐습니다.",
              response.status
            );
          }
          if (!payload) {
            throw new ApiError("BAD_RESPONSE", "서버 응답을 해석하지 못했습니다.", response.status);
          }
          return payload;
        });
      },
      function () {
        // A transport failure says nothing about whether the server acted, which is exactly
        // why the identifier is held: retrying replays instead of repeating.
        throw new ApiError("NETWORK", ERROR_MESSAGES.NETWORK, 0);
      }
    );
  }

  // ── busy, status and error surfaces ─────────────────────────────────────────────────

  function setBusy(busy, button) {
    ui.busy = busy;
    var controls = document.querySelectorAll(
      ".board__cell, .outside__cell, .button, .chips input, .bet-types input"
    );
    for (var i = 0; i < controls.length; i += 1) {
      controls[i].disabled = busy;
    }
    document.querySelector(".app").setAttribute("aria-busy", busy ? "true" : "false");
    var buttons = [el.clear, el.rebet, el.spin, el.newRound];
    for (var j = 0; j < buttons.length; j += 1) {
      buttons[j].classList.toggle("is-busy", busy && buttons[j] === button);
    }
    if (!busy && ui.server) {
      // Re-derive which controls are legal now rather than restoring what was disabled
      // before, since the round may have moved on while the request was in flight.
      renderBoard(ui.server);
      renderControls();
    }
  }

  function setStatus(text, tone) {
    el.status.textContent = text;
    if (tone) {
      el.status.setAttribute("data-tone", tone);
    } else {
      el.status.removeAttribute("data-tone");
    }
  }

  function announce(text) {
    // Cleared first so a repeated message is still a change, and is still spoken.
    el.announcer.textContent = "";
    el.announcer.textContent = text;
  }

  function showError(error, retryAction) {
    var message = ERROR_MESSAGES[error.code] || error.message || "요청이 거절됐습니다.";
    el.errorMessage.textContent = message + " (" + error.code + ")";
    el.errorAlert.hidden = false;
    ui.retryAction = retryAction || null;
    el.retry.hidden = !ui.retryAction;
  }

  function clearError() {
    el.errorAlert.hidden = true;
    el.retry.hidden = true;
    el.errorMessage.textContent = "";
    ui.retryAction = null;
  }

  /*
   * One action at a time, end to end. The guard is the reason a double click, a double tap
   * and an impatient Enter key cannot start a second spin: the second call returns before
   * it reaches the network, and every control is disabled for the duration besides.
   */
  function run(name, button, work) {
    if (ui.busy) {
      return Promise.resolve();
    }
    clearError();
    setBusy(true, button);
    return work()
      .catch(function (error) {
        // `role="alert"` announces the message on its own, so nothing is sent to the polite
        // region here: one failure should not be read out twice.
        showError(error, function () {
          run(name, button, work);
        });
        setStatus("요청이 완료되지 않았습니다. 아래 안내를 확인해 주세요.");
      })
      .then(function () {
        setBusy(false, button);
      });
  }

  // ── rendering ───────────────────────────────────────────────────────────────────────

  function applyState(state) {
    ui.server = state;
    renderNotice(state);
    renderBalance(state);
    renderRound(state);
    renderHistory(state);
    renderSelectionCounts(state);
    renderBoard(state);
    renderSlip(state);
    renderControls();
  }

  function renderNotice(state) {
    if (state.notice && state.notice.text_ko) {
      el.serverNotice.textContent = state.notice.text_ko;
    }
    el.tableId.textContent = state.table_id + " · " + state.currency;
  }

  function renderBalance(state) {
    var changed = ui.lastBalance !== null && ui.lastBalance !== state.balance_units;
    el.balance.textContent = chips(state.balance_units);
    el.reserved.textContent = chips(state.reserved_units);
    el.available.textContent = chips(state.available_units);
    if (changed) {
      el.balance.classList.remove("is-updated");
      void el.balance.offsetWidth;
      el.balance.classList.add("is-updated");
    }
    ui.lastBalance = state.balance_units;
  }

  function renderRound(state) {
    var round = state.round;
    el.phase.textContent = PHASE_LABELS[round.phase] || round.phase;
    el.phase.setAttribute("data-phase", round.phase);
    el.roundId.textContent = round.round_id;

    var result = round.result;
    if (result) {
      el.pocketValue.textContent = String(result.pocket);
      el.pocketLabel.textContent =
        (COLOR_LABELS[result.color] || result.color) + " · " + round.round_id;
      el.pocket.setAttribute("data-color", result.color);
      el.settlement.hidden = false;
      el.settlementStake.textContent = chips(result.total_stake_units);
      el.settlementReturn.textContent = chips(result.total_return_units);
      el.settlementNet.textContent = signedChips(result.net_change_units);
      el.settlementNet.setAttribute(
        "data-sign",
        result.net_change_units > 0 ? "positive" : result.net_change_units < 0 ? "negative" : "flat"
      );
    } else {
      el.pocketValue.textContent = "–";
      el.pocketLabel.textContent = "아직 결과 없음";
      el.pocket.setAttribute("data-color", "none");
      el.pocket.classList.remove("is-revealed");
      el.settlement.hidden = true;
    }
  }

  function renderHistory(state) {
    var recent = (state.recent_results || []).slice().reverse();
    el.history.textContent = "";
    if (!recent.length) {
      var empty = document.createElement("li");
      empty.className = "history__empty";
      empty.textContent = "아직 기록이 없습니다.";
      el.history.appendChild(empty);
      return;
    }
    for (var i = 0; i < recent.length; i += 1) {
      var entry = recent[i];
      var item = document.createElement("li");
      item.className = "history__item";
      item.setAttribute("data-color", entry.color);
      item.textContent = String(entry.pocket);
      // Colour is decorative; the accessible name carries the same information as words.
      item.setAttribute(
        "aria-label",
        i + 1 + "번째 이전 결과, " + entry.pocket + ", " + (COLOR_LABELS[entry.color] || entry.color)
      );
      el.history.appendChild(item);
    }
  }

  function renderSelectionCounts(state) {
    var counts = state.table.bet_selection_counts;
    var nodes = document.querySelectorAll("[data-count-for]");
    for (var i = 0; i < nodes.length; i += 1) {
      var type = nodes[i].getAttribute("data-count-for");
      if (Object.prototype.hasOwnProperty.call(counts, type)) {
        nodes[i].textContent = "번호 " + counts[type] + "개";
      }
    }
    updateSelectionHint();
  }

  function updateSelectionHint() {
    var required = requiredSelections(ui.betType);
    if (required === null) {
      el.selectionHint.textContent = "테이블 정보를 불러오는 중입니다.";
      return;
    }
    el.selectionHint.textContent =
      typeLabel(ui.betType) +
      " 베팅: 번호 " +
      required +
      "개를 고르면 " +
      chips(ui.chip) +
      "이 슬립에 담깁니다. 조합이 규칙에 맞는지는 서버가 판정합니다. " +
      payoutRatioLabel(ui.betType);
  }

  /* The board is built once from the pockets the server publishes, then only its state
     attributes are touched, so a re-render never costs 37 element constructions. */
  function buildBoard(state) {
    var pockets = state.table.pockets;
    var colors = state.table.pocket_colors;
    el.board.textContent = "";
    ui.wheelPockets = pockets.slice();
    for (var i = 0; i < pockets.length; i += 1) {
      var pocket = pockets[i];
      // The single green pocket is the zero, and the server is what says so.
      var color = pocketColor(colors, pocket);
      var isZero = color === "green";
      var cell = document.createElement("button");
      cell.type = "button";
      cell.className = "board__cell" + (isZero ? " board__cell--zero" : "");
      cell.setAttribute("data-pocket", String(pocket));
      cell.setAttribute("aria-pressed", "false");
      cell.setAttribute("data-color", color);
      var label = document.createElement("span");
      label.className = "board__cell-value";
      label.textContent = String(pocket);
      cell.appendChild(label);
      if (!isZero) {
        // The wide desktop board is the classic three-row layout; these two custom
        // properties place each number in it without a class per column.
        cell.style.setProperty("--col", String(2 + Math.floor((pocket - 1) / 3)));
        cell.style.setProperty("--row", String(3 - ((pocket - 1) % 3)));
      }
      el.board.appendChild(cell);
    }
  }

  function stakedOnPocket(pocket) {
    var total = 0;
    var all = ui.drafts.concat(
      ui.server && ui.server.round ? ui.server.round.bets : []
    );
    for (var i = 0; i < all.length; i += 1) {
      var bet = all[i];
      var selections = bet.selections || [];
      if (!selections.length || isIndexSelectionType(bet.type)) {
        continue;
      }
      if (selections.indexOf(pocket) !== -1) {
        total += bet.stake_units;
      }
    }
    return total;
  }

  function renderBoard(state) {
    if (!el.board.firstChild) {
      buildBoard(state);
    }
    var open = state.round.accepts_bets;
    var cells = el.board.querySelectorAll(".board__cell");
    for (var i = 0; i < cells.length; i += 1) {
      var cell = cells[i];
      var pocket = Number(cell.getAttribute("data-pocket"));
      var selected = ui.selection.indexOf(pocket) !== -1;
      cell.setAttribute("aria-pressed", selected ? "true" : "false");
      var staked = stakedOnPocket(pocket);
      setCellChip(cell, staked);
      var color = cell.getAttribute("data-color");
      cell.setAttribute(
        "aria-label",
        "번호 " +
          pocket +
          ", " +
          (COLOR_LABELS[color] || color) +
          (staked ? ", 베팅 " + chips(staked) : "") +
          (selected ? ", 선택됨" : "")
      );
      if (!ui.busy) {
        cell.disabled = !open;
      }
    }
    var outside = document.querySelectorAll(".outside__cell");
    for (var j = 0; j < outside.length; j += 1) {
      var button = outside[j];
      var type = button.getAttribute("data-bet-type");
      var raw = button.getAttribute("data-selections");
      var staked2 = stakedOnOutside(type, raw);
      setCellChip(button, staked2);
      button.setAttribute(
        "aria-label",
        outsideLabel(type, raw) +
          " 베팅, " +
          chips(ui.chip) +
          " 담기" +
          (staked2 ? ", 현재 " + chips(staked2) : "")
      );
      if (!ui.busy) {
        button.disabled = !open;
      }
    }
  }

  function outsideLabel(type, raw) {
    if (type === "dozen") {
      return DOZEN_LABELS[Number(raw)] || typeLabel(type);
    }
    if (type === "column") {
      return COLUMN_LABELS[Number(raw)] || typeLabel(type);
    }
    return typeLabel(type);
  }

  function stakedOnOutside(type, raw) {
    var wanted = raw === "" ? null : Number(raw);
    var all = ui.drafts.concat(ui.server && ui.server.round ? ui.server.round.bets : []);
    var total = 0;
    for (var i = 0; i < all.length; i += 1) {
      var bet = all[i];
      if (bet.type !== type) {
        continue;
      }
      var selections = bet.selections || [];
      if (wanted === null ? selections.length === 0 : selections[0] === wanted) {
        total += bet.stake_units;
      }
    }
    return total;
  }

  function setCellChip(cell, units) {
    var mark = cell.querySelector(".cell-chip");
    if (!units) {
      if (mark) {
        cell.removeChild(mark);
      }
      return;
    }
    if (!mark) {
      mark = document.createElement("span");
      mark.className = "cell-chip is-new";
      mark.setAttribute("aria-hidden", "true");
      cell.appendChild(mark);
    }
    mark.textContent = numberFormat.format(units);
  }

  function renderSlip(state) {
    var placed = state.round.bets || [];
    var outcomes = state.round.result ? state.round.result.outcomes : null;

    el.draftCount.textContent = String(ui.drafts.length);
    el.placedCount.textContent = String(placed.length);

    renderSlipList(el.draftList, ui.drafts, null, "담은 베팅이 없습니다.");
    renderSlipList(el.placedList, placed, outcomes, "확정된 베팅이 없습니다.");

    var total = state.round.total_stake_units;
    for (var i = 0; i < ui.drafts.length; i += 1) {
      total += ui.drafts[i].stake_units;
    }
    el.slipTotal.textContent = chips(total);
  }

  function renderSlipList(list, bets, outcomes, emptyText) {
    list.textContent = "";
    if (!bets.length) {
      var empty = document.createElement("li");
      empty.className = "slip__empty";
      empty.textContent = emptyText;
      list.appendChild(empty);
      return;
    }
    for (var i = 0; i < bets.length; i += 1) {
      var bet = bets[i];
      var item = document.createElement("li");
      item.className = "slip__item";
      if (bet.draft_id && ui.freshDraftIds[bet.draft_id]) {
        item.classList.add("is-new");
        delete ui.freshDraftIds[bet.draft_id];
      }

      var label = document.createElement("span");
      label.className = "slip__item-label";
      label.textContent = betLabel(bet);
      item.appendChild(label);

      var outcome = outcomes && outcomes[i] ? outcomes[i] : null;
      if (outcome) {
        // Won, lost and the amount returned are the server's words, copied onto the screen.
        item.setAttribute("data-outcome", outcome.won ? "won" : "lost");
        var verdict = document.createElement("span");
        verdict.className = "slip__item-outcome";
        verdict.textContent = outcome.won
          ? "적중 · 지급 " + chips(outcome.payout_units)
          : "미적중 · " + signedChips(outcome.net_change_units);
        item.appendChild(verdict);
      }

      var stake = document.createElement("span");
      stake.className = "slip__item-stake";
      stake.textContent = chips(bet.stake_units);
      item.appendChild(stake);

      list.appendChild(item);
    }
  }

  function renderControls() {
    if (ui.busy || !ui.server) {
      return;
    }
    var round = ui.server.round;
    el.clear.disabled = ui.drafts.length === 0;
    el.rebet.disabled = !round.accepts_bets || ui.lastRoundBets.length === 0;
    el.spin.disabled = !round.accepts_bets || (ui.drafts.length === 0 && round.bet_count === 0);
    el.newRound.disabled = !round.is_terminal;
  }

  // ── wheel ───────────────────────────────────────────────────────────────────────────

  function buildWheel(state) {
    var pockets = state.table.pockets;
    var colors = state.table.pocket_colors;
    var layout = WHEEL_LAYOUT.length === pockets.length ? WHEEL_LAYOUT : pockets;
    for (var i = 0; i < layout.length; i += 1) {
      if (pockets.indexOf(layout[i]) === -1) {
        layout = pockets; // the server knows a different table; draw that one instead
        break;
      }
    }
    ui.wheelLayout = layout;

    var svgNs = "http://www.w3.org/2000/svg";
    var step = 360 / layout.length;
    el.rotor.textContent = "";
    for (var j = 0; j < layout.length; j += 1) {
      var pocket = layout[j];
      var start = -90 + j * step - step / 2;
      var end = start + step;
      var wedge = document.createElementNS(svgNs, "path");
      wedge.setAttribute("d", annulusSector(38, 96, start, end));
      wedge.setAttribute(
        "class",
        "wheel__pocket-edge wheel__pocket-" + pocketColor(colors, pocket)
      );
      el.rotor.appendChild(wedge);

      var text = document.createElementNS(svgNs, "text");
      var mid = (start + end) / 2;
      var point = polar(78, mid);
      text.setAttribute("x", point.x.toFixed(2));
      text.setAttribute("y", point.y.toFixed(2));
      text.setAttribute("class", "wheel__number");
      text.setAttribute(
        "transform",
        "rotate(" + (mid + 90).toFixed(2) + " " + point.x.toFixed(2) + " " + point.y.toFixed(2) + ")"
      );
      text.textContent = String(pocket);
      el.rotor.appendChild(text);
    }
  }

  function polar(radius, degrees) {
    var radians = (degrees * Math.PI) / 180;
    return { x: radius * Math.cos(radians), y: radius * Math.sin(radians) };
  }

  function annulusSector(inner, outer, startDeg, endDeg) {
    var a = polar(outer, startDeg);
    var b = polar(outer, endDeg);
    var c = polar(inner, endDeg);
    var d = polar(inner, startDeg);
    var large = endDeg - startDeg > 180 ? 1 : 0;
    return (
      "M" + a.x.toFixed(2) + " " + a.y.toFixed(2) +
      "A" + outer + " " + outer + " 0 " + large + " 1 " + b.x.toFixed(2) + " " + b.y.toFixed(2) +
      "L" + c.x.toFixed(2) + " " + c.y.toFixed(2) +
      "A" + inner + " " + inner + " 0 " + large + " 0 " + d.x.toFixed(2) + " " + d.y.toFixed(2) +
      "Z"
    );
  }

  /*
   * Turn the rotor until the server's pocket sits under the pointer. The angle is a pure
   * function of the pocket that already came back from `/api/spin`; nothing here decides
   * anything, and if the layout does not contain the pocket the wheel simply does not move.
   */
  function spinWheelTo(pocket) {
    var layout = ui.wheelLayout || [];
    var index = layout.indexOf(pocket);
    if (index === -1) {
      return Promise.resolve();
    }
    var step = 360 / layout.length;
    var extraTurns = prefersReducedMotion() ? 0 : SPIN_EXTRA_TURNS;
    ui.wheelTurn += extraTurns;
    var angle = ui.wheelTurn * 360 - index * step;
    el.rotor.style.setProperty("--wheel-turn", angle.toFixed(3) + "deg");
    if (prefersReducedMotion()) {
      return Promise.resolve();
    }
    return new Promise(function (resolve) {
      window.setTimeout(resolve, SPIN_ANIMATION_MS);
    });
  }

  // ── actions ─────────────────────────────────────────────────────────────────────────

  function loadState() {
    return request("GET", "/api/state").then(function (payload) {
      if (!el.rotor.firstChild) {
        buildWheel(payload.state);
      }
      applyState(payload.state);
      setStatus(
        "베팅을 담고 스핀을 누르세요. 결과와 잔액은 서버가 결정합니다. 가상 칩이며 현금 가치가 없습니다."
      );
    });
  }

  /*
   * A draft carries the identifier it will eventually be submitted under. Minting it here
   * rather than at submission time is what makes a partially failed submission safe to
   * retry: the bets the server already accepted replay under their original identifiers
   * instead of being placed a second time.
   */
  function makeDraft(type, selections, stakeUnits) {
    var draft = {
      draft_id: newRequestId("BET"),
      type: type,
      selections: selections.slice(),
      stake_units: stakeUnits,
    };
    draft.request_id = draft.draft_id;
    ui.freshDraftIds[draft.draft_id] = true;
    return draft;
  }

  function addDraft(type, selections) {
    if (!ui.server || !ui.server.round.accepts_bets) {
      return;
    }
    var limits = ui.server.limits;
    if (ui.chip < limits.min_stake_units || ui.chip > limits.max_stake_units) {
      showError(
        new ApiError("STAKE_OUT_OF_RANGE", "서버가 허용한 베팅 금액 범위를 벗어났습니다."),
        null
      );
      return;
    }
    if (ui.server.round.bet_count + ui.drafts.length >= limits.max_bets_per_round) {
      showError(new ApiError("BET_LIMIT_REACHED", ERROR_MESSAGES.BET_LIMIT_REACHED), null);
      return;
    }
    var draft = makeDraft(type, selections, ui.chip);
    ui.drafts.push(draft);
    clearError();
    applyState(ui.server);
    var text = betLabel(draft) + " " + chips(draft.stake_units) + " 담았습니다.";
    setStatus(text + " 스핀을 누르면 서버에 제출됩니다.");
    announce(text);
  }

  function submitDrafts() {
    if (!ui.drafts.length) {
      return Promise.resolve();
    }
    var draft = ui.drafts[0];
    return request("POST", "/api/bets", {
      request_id: draft.request_id,
      bet: {
        type: draft.type,
        selections: draft.selections,
        stake_units: draft.stake_units,
      },
    }).then(function (payload) {
      ui.drafts.shift();
      applyState(payload.state);
      return submitDrafts();
    });
  }

  function doSpin() {
    return run("spin", el.spin, function () {
      setStatus("베팅을 서버에 제출하는 중입니다.", "busy");
      return submitDrafts().then(function () {
        var requestId = heldRequestId("spin", "SPIN");
        setStatus("서버가 추첨하는 중입니다.", "busy");
        announce("서버가 추첨하는 중입니다.");
        return request("POST", "/api/spin", { request_id: requestId }).then(function (payload) {
          releaseRequestId("spin");
          ui.lastRoundBets = (payload.state.round.bets || []).map(function (bet) {
            return { type: bet.type, selections: bet.selections, stake_units: bet.stake_units };
          });
          return spinWheelTo(payload.result.pocket).then(function () {
            applyState(payload.state);
            el.pocket.classList.add("is-revealed");
            var result = payload.result;
            var summary =
              "결과 " +
              result.pocket +
              " " +
              (COLOR_LABELS[result.color] || result.color) +
              ". 서버 지급 " +
              chips(result.total_return_units) +
              ", 증감 " +
              signedChips(result.net_change_units) +
              ", 잔액 " +
              chips(payload.state.balance_units) +
              ".";
            setStatus(
              summary + " 새 라운드를 열어 계속하세요.",
              result.net_change_units > 0 ? "win" : null
            );
            announce(summary);
          });
        });
      });
    });
  }

  function doNewRound() {
    return run("new-round", el.newRound, function () {
      var requestId = heldRequestId("new-round", "ROUND");
      return request("POST", "/api/new-round", { request_id: requestId }).then(function (payload) {
        releaseRequestId("new-round");
        ui.selection = [];
        ui.drafts = [];
        applyState(payload.state);
        setStatus("새 라운드가 열렸습니다. 베팅을 담아 주세요.");
        announce("새 라운드 " + payload.state.round.round_id + "가 열렸습니다.");
      });
    });
  }

  function doClear() {
    if (ui.busy || !ui.drafts.length) {
      return;
    }
    ui.drafts = [];
    ui.selection = [];
    clearError();
    applyState(ui.server);
    setStatus("대기 중이던 베팅을 모두 지웠습니다. 서버가 확정한 베팅은 취소할 수 없습니다.");
    announce("대기 중이던 베팅을 지웠습니다.");
  }

  function doRebet() {
    if (ui.busy || !ui.server || !ui.server.round.accepts_bets) {
      return;
    }
    if (!ui.lastRoundBets.length) {
      return;
    }
    for (var i = 0; i < ui.lastRoundBets.length; i += 1) {
      var previous = ui.lastRoundBets[i];
      ui.drafts.push(makeDraft(previous.type, previous.selections, previous.stake_units));
    }
    clearError();
    applyState(ui.server);
    setStatus("직전 라운드와 같은 베팅 " + ui.lastRoundBets.length + "건을 다시 담았습니다.");
    announce("직전 라운드 베팅을 다시 담았습니다.");
  }

  // ── input wiring ────────────────────────────────────────────────────────────────────

  function onBoardClick(event) {
    var cell = event.target.closest(".board__cell");
    if (!cell || ui.busy || cell.disabled) {
      return;
    }
    var pocket = Number(cell.getAttribute("data-pocket"));
    var required = requiredSelections(ui.betType);
    if (required === null || required < 1) {
      return;
    }
    var at = ui.selection.indexOf(pocket);
    if (at !== -1) {
      ui.selection.splice(at, 1);
    } else {
      ui.selection.push(pocket);
    }
    if (ui.selection.length >= required) {
      var selections = ui.selection.slice(0, required);
      ui.selection = [];
      addDraft(ui.betType, selections);
      return;
    }
    applyState(ui.server);
    var remaining = required - ui.selection.length;
    setStatus(
      typeLabel(ui.betType) + " 베팅: 번호 " + remaining + "개를 더 고르세요. 선택 " +
        ui.selection.join(", ") + "."
    );
    announce("번호 " + pocket + (at !== -1 ? " 선택 해제" : " 선택") + ", " + remaining + "개 남음");
  }

  function onOutsideClick(event) {
    var button = event.target.closest(".outside__cell");
    if (!button || ui.busy || button.disabled) {
      return;
    }
    var type = button.getAttribute("data-bet-type");
    var raw = button.getAttribute("data-selections");
    ui.selection = [];
    addDraft(type, raw === "" ? [] : [Number(raw)]);
  }

  function onChipChange(event) {
    var input = event.target;
    if (!input || input.name !== "chip") {
      return;
    }
    ui.chip = Number(input.value);
    updateSelectionHint();
    if (ui.server) {
      renderBoard(ui.server);
    }
    announce("칩 " + chips(ui.chip) + " 선택");
  }

  function onBetTypeChange(event) {
    var input = event.target;
    if (!input || input.name !== "bet-type") {
      return;
    }
    ui.betType = input.value;
    ui.selection = [];
    updateSelectionHint();
    if (ui.server) {
      renderBoard(ui.server);
    }
    announce(el.selectionHint.textContent);
  }

  function wire() {
    el.board.addEventListener("click", onBoardClick);
    document.querySelector(".outside").addEventListener("click", onOutsideClick);
    document.getElementById("chip-group").addEventListener("change", onChipChange);
    document.getElementById("bet-type-group").addEventListener("change", onBetTypeChange);
    el.spin.addEventListener("click", doSpin);
    el.newRound.addEventListener("click", doNewRound);
    el.clear.addEventListener("click", doClear);
    el.rebet.addEventListener("click", doRebet);
    el.retry.addEventListener("click", function () {
      var action = ui.retryAction;
      clearError();
      if (action) {
        action();
      }
    });
  }

  function start() {
    wire();
    el.retry.hidden = true;
    setBusy(true, null);
    loadState()
      .catch(function (error) {
        showError(error, function () {
          run("reload", null, loadState);
        });
        setStatus("테이블을 불러오지 못했습니다.");
      })
      .then(function () {
        setBusy(false, null);
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
