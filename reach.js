/* Reach Greg — the site's SIP reach-me line.
 *
 * Browser mic -> wss://<this host>/reach -> the bridge on
 * Greg's box -> AudioSocket -> Asterisk -> his desk phone (101)
 * and his cell (SIP softphone) ring in parallel. No PSTN anywhere.
 *
 * States: idle -> connecting -> ringing -> live -> voicemail -> done.
 * Audio is raw int16 8 kHz mono in binary websocket frames.
 */
(function () {
  "use strict";

  var REACH_URL =
    (location.protocol === "https:" ? "wss://" : "ws://") +
    location.host + "/reach";

  var state = "idle";
  var ws = null;
  var audioCtx = null;
  var processor = null;
  var micStream = null;
  var source = null;
  var liveGain = null;
  var hqSong = null;   // full-quality hold song, played locally while ringing
  var busyNotice = null; // "Greg is on another call" line, played once
  var announced = false; // the busy notice fires only once per call
  var playHead = 0;    // scheduled playback time for Greg's voice (jitter buffer)
  var timerId = null;
  var seconds = 0;

  var STATUS_TEXT = {
    connecting: "Connecting…",
    ringing: "Ringing Greg's phone…",
    live: "Connected — talk freely",
    voicemail: "Leave your message…",
    done: "Message sent — thank you"
  };

  function el(id) { return document.getElementById(id); }

  function setState(s) {
    state = s;
    var btn = el("reach-btn");
    var panel = el("reach-panel");
    if (btn) {
      btn.disabled = (s === "connecting" || s === "ringing" ||
                      s === "live" || s === "voicemail");
    }
    if (panel) {
      panel.className = "reach-panel reach-" + s;
      panel.hidden = (s === "idle");
    }
    var status = el("reach-status");
    if (status) {
      status.textContent = STATUS_TEXT[s] || "";
    }
  }

  function log(msg) {
    var box = el("reach-log");
    if (box) {
      box.textContent = msg;
    }
  }

  function cleanup() {
    stopSong();
    if (processor) {
      try { processor.disconnect(); } catch (e) {}
      processor = null;
    }
    if (workletNode) {
      try { workletNode.port.onmessage = null; workletNode.disconnect(); }
      catch (e) {}
      workletNode = null;
    }
    if (workletUrl) {
      try { URL.revokeObjectURL(workletUrl); } catch (e) {}
      workletUrl = null;
    }
    if (source) {
      try { source.disconnect(); } catch (e) {}
      source = null;
    }
    if (micStream) {
      micStream.getTracks().forEach(function (t) { t.stop(); });
      micStream = null;
    }
    playHead = 0;
    micFrame = [];
    announced = false;
    if (audioCtx) {
      try { audioCtx.close(); } catch (e) {}
      audioCtx = null;
    }
    if (timerId) {
      clearInterval(timerId);
      timerId = null;
    }
    if (ws) {
      try { ws.close(); } catch (e) {}
      ws = null;
    }
  }

  // ---- hold song (full quality, played right here) ----------------

  function stopSong() {
    if (hqSong) {
      try { hqSong.pause(); } catch (e) {}
      hqSong = null;
    }
    if (busyNotice) {
      try { busyNotice.pause(); } catch (e) {}
      busyNotice = null;
    }
  }

  function playSong(url) {
    if (!url) return;
    if (hqSong && hqSong.dataset.url === url && !hqSong.paused) return;
    stopSong();
    var a = new Audio(url);
    a.dataset.url = url;
    a.loop = true;
    a.volume = 0.85;
    a.preload = 'auto';
    a.playsInline = true;
    a.muted = false;
    hqSong = a;
    var p = a.play();
    if (p && p.catch) {
      p.catch(function (e) {
        try { a.muted = true; a.play(); } catch (ex) {}
      });
    }
  }

  // Greg is already on a call: say so once, then loop the hold song.
  // His phone still rings (call waiting), so he can pick up the second line.
  function busyHold(noticeUrl, songUrl) {
    if (!noticeUrl || announced) { playSong(songUrl); return; }
    announced = true;
    stopSong();
    var a = new Audio(noticeUrl);
    a.volume = 0.95;
    a.preload = 'auto';
    a.playsInline = true;
    busyNotice = a;
    var toSong = function () {
      if (busyNotice === a) { busyNotice = null; }
      playSong(songUrl);
    };
    a.addEventListener("ended", toSong);
    var p = a.play();
    if (p && p.catch) {
      p.catch(function () {
        try { a.muted = true; a.play().catch(toSong); } catch (e) { toSong(); }
      });
    }
  }

  function handleControl(text) {
    var msg;
    try { msg = JSON.parse(text); } catch (e) { return; }
    if (!msg || msg.type !== "state") return;
    playHead = 0;
    if (msg.state === "ringing" && msg.busy) {
      busyHold(msg.announce, msg.song);
      setState("ringing");
      log("Greg is on another call — you're next. One moment please.");
      return;
    }
    if (msg.state === "ringing") {
      playSong(msg.song);
    } else {
      stopSong();
    }
    setState(msg.state);
  }

  function startTimer() {
    seconds = 0;
    var t = el("reach-timer");
    timerId = setInterval(function () {
      seconds++;
      if (t) {
        t.textContent = Math.floor(seconds / 60) + ":" +
          ("0" + (seconds % 60)).slice(-2);
      }
    }, 1000);
  }

  function sendBye() {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "bye" }));
    }
  }

  function hangup() {
    sendBye();
    cleanup();
    setState("idle");
    log("");
  }

  // ---- audio plumbing ---------------------------------------------

  function floatTo16(f) {
    var s = Math.max(-1, Math.min(1, f));
    return s < 0 ? s * 0x8000 : s * 0x7FFF;
  }

  // Mic capture runs in an AudioWorklet that decimates to 8 kHz and emits
  // steady 20 ms frames (160 samples). The old ScriptProcessor used a
  // 4096-sample buffer — up to half a second of audio per chunk — which
  // starved the phone leg and made speech choppy.
  var workletNode = null;
  var workletUrl = null;

  var CAPTURE_WORKLET = [
    "class ReachCapture extends AudioWorkletProcessor {",
    "  constructor() {",
    "    super();",
    "    this.step = sampleRate / 8000;",
    "    this.phase = 0;",
    "    this.acc = 0;",
    "    this.n = 0;",
    "    this.frame = new Float32Array(160);",
    "    this.f = 0;",
    "  }",
    "  process(inputs) {",
    "    var ch = inputs[0] && inputs[0][0];",
    "    if (ch) {",
    "      for (var i = 0; i < ch.length; i++) {",
    "        this.acc += ch[i]; this.n++; this.phase += 1;",
    "        if (this.phase >= this.step) {",
    "          this.frame[this.f++] = this.acc / this.n;",
    "          this.acc = 0; this.n = 0; this.phase -= this.step;",
    "          if (this.f >= 160) {",
    "            var out = new Int16Array(160);",
    "            for (var k = 0; k < 160; k++) {",
    "              var v = Math.max(-1, Math.min(1, this.frame[k]));",
    "              out[k] = v < 0 ? v * 32768 : v * 32767;",
    "            }",
    "            this.port.postMessage(out.buffer, [out.buffer]);",
    "            this.f = 0;",
    "          }",
    "        }",
    "      }",
    "    }",
    "    return true;",
    "  }",
    "}",
    "registerProcessor('reach-capture', ReachCapture);"
  ].join("\n");

  // Fallback when AudioWorklet is unavailable: 1024-sample ScriptProcessor
  // with the same decimation and 20 ms framing on the main thread.
  var micStep = 6, micPhase = 0, micAcc = 0, micN = 0, micFrame = [];

  function onMic(e) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    var input = e.inputBuffer.getChannelData(0);
    for (var i = 0; i < input.length; i++) {
      micAcc += input[i]; micN++; micPhase += 1;
      if (micPhase >= micStep) {
        micFrame.push(micAcc / micN);
        micAcc = 0; micN = 0; micPhase -= micStep;
        if (micFrame.length >= 160) {
          var out = new Int16Array(160);
          for (var k = 0; k < 160; k++) out[k] = floatTo16(micFrame[k]);
          ws.send(out.buffer);
          micFrame = [];
        }
      }
    }
  }

  function muteTail(node) {
    var mute = audioCtx.createGain();
    mute.gain.value = 0;
    node.connect(mute);
    mute.connect(audioCtx.destination);
  }

  function startWorkletCapture() {
    workletUrl = URL.createObjectURL(new Blob(
      [CAPTURE_WORKLET], { type: "application/javascript" }));
    return audioCtx.audioWorklet.addModule(workletUrl).then(function () {
      workletNode = new AudioWorkletNode(audioCtx, "reach-capture",
        { numberOfInputs: 1, numberOfOutputs: 1,
          outputChannelCount: [1] });
      workletNode.port.onmessage = function (ev) {
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(ev.data);
      };
      source.connect(workletNode);
      muteTail(workletNode);
    });
  }

  function startMic() {
    return navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true,
               autoGainControl: true }
    }).then(function (stream) {
      micStream = stream;
      audioCtx = new (window.AudioContext ||
                      window.webkitAudioContext)(
        { latencyHint: "interactive" });
      source = audioCtx.createMediaStreamSource(stream);
      // playback path for Greg's voice, the song, the greeting
      liveGain = audioCtx.createGain();
      liveGain.gain.value = 1.0;
      liveGain.connect(audioCtx.destination);
      playHead = 0;
      // capture path: worklet first, ScriptProcessor only as a fallback
      if (audioCtx.audioWorklet) {
        return startWorkletCapture();
      }
      micStep = audioCtx.sampleRate / 8000;
      processor = audioCtx.createScriptProcessor(1024, 1, 1);
      processor.onaudioprocess = onMic;
      source.connect(processor);
      muteTail(processor);
    });
  }

  // Greg's voice is scheduled ~150 ms ahead of the clock so bursts and
  // gaps in network delivery land inside the buffer instead of as clicks.
  var JITTER_LEAD = 0.15;

  function onWsBinary(data) {
    // While ringing, the 8 kHz song stream is replaced by the
    // full-quality song playing locally — drop the narrowband copy.
    if (state === "ringing") return;
    if (!audioCtx) {
      audioCtx = new (window.AudioContext ||
                      window.webkitAudioContext)(
        { latencyHint: "interactive" });
      liveGain = audioCtx.createGain();
      liveGain.gain.value = 1.0;
      liveGain.connect(audioCtx.destination);
      playHead = 0;
    }
    var ints = new Int16Array(data);
    if (!ints.length) return;
    var floats = new Float32Array(ints.length);
    for (var i = 0; i < ints.length; i++) {
      floats[i] = ints[i] / 32768;
    }
    var buf = audioCtx.createBuffer(1, floats.length, 8000);
    buf.copyToChannel(floats, 0);
    var now = audioCtx.currentTime;
    if (playHead === 0) {
      playHead = now + JITTER_LEAD;        // first frame: fill the buffer
    } else if (playHead < now + 0.005) {
      playHead = now + 0.05;               // underrun: recover gently
    } else if (playHead > now + 0.6) {
      playHead = now + JITTER_LEAD;        // too far ahead: re-seat
    }
    var src = audioCtx.createBufferSource();
    src.buffer = buf;
    src.connect(liveGain);
    src.start(playHead);
    playHead += buf.duration;
  }

  // ---- main flow --------------------------------------------------

  function start(name, problem) {
    setState("connecting");
    var url = REACH_URL + "?name=" + encodeURIComponent(name) +
              "&problem=" + encodeURIComponent(problem);
    ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";

    ws.onopen = function () {
      setState("ringing");
      startMic().catch(function () {
        log("I couldn't reach your microphone — check the browser permission.");
      });
    };

    ws.onmessage = function (e) {
      if (typeof e.data === "string") {
        handleControl(e.data);
        return;
      }
      if (e.data instanceof ArrayBuffer && e.data.byteLength > 0) {
        onWsBinary(e.data);
      }
    };

    ws.onerror = function () {
      log("The reach line is having a moment — try again in a bit.");
      cleanup();
      setState("idle");
    };

    ws.onclose = function () {
      if (state === "ringing" || state === "voicemail" ||
          state === "live") {
        setState("done");
        setTimeout(function () {
          cleanup();
          setState("idle");
          log("");
        }, 2500);
      } else {
        cleanup();
        setState("idle");
      }
    };

    startTimer();
  }

  // ---- wire up the mount point ------------------------------------

  function mount() {
    var mount = document.getElementById("reach-greg");
    if (!mount || mount.dataset.bound) return;
    mount.dataset.bound = "1";

    mount.innerHTML =
      '<button id="reach-btn" class="reach-btn" type="button">' +
      "Reach Greg — call from this page</button>" +
      '<div id="reach-panel" class="reach-panel" hidden>' +
      '  <div class="reach-top">' +
      '    <span id="reach-status"></span>' +
      '    <span id="reach-timer" class="reach-timer"></span>' +
      '  </div>' +
      '  <div id="reach-log" class="reach-log"></div>' +
      '  <div class="reach-actions">' +
      '    <button id="reach-hangup" class="reach-hangup" ' +
      '            type="button">Hang up</button>' +
      '  </div>' +
      '</div>';

    el("reach-btn").addEventListener("click", function () {
      var name = prompt("Your name:", "");
      if (name === null) return; // cancelled
      var problem = prompt("What do you need?", "");
      if (problem === null) return; // cancelled
      start(name.trim() || "a visitor", problem.trim());
    });
    el("reach-hangup").addEventListener("click", hangup);

    setState("idle");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount);
  } else {
    mount();
  }
})();
