/* Secure OTA -- the whole page, in one file.
 *
 * Nothing security-relevant happens in the browser. This asks the server to
 * upload, package and publish, and renders what it answers. No key ever
 * reaches this file, and no value shown here is trusted by the device.
 */

(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  function esc(value) {
    return String(value === null || value === undefined ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function bytes(n) {
    n = Number(n) || 0;
    if (n < 1024) { return n + " B"; }
    if (n < 1024 * 1024) { return (n / 1024).toFixed(1) + " KB"; }
    return (n / (1024 * 1024)).toFixed(2) + " MB";
  }

  function when(epochSeconds) {
    if (!epochSeconds) { return "—"; }
    return new Date(epochSeconds * 1000).toLocaleString();
  }

  function toast(message, kind) {
    var el = document.createElement("div");
    el.className = "toast" + (kind ? " " + kind : "");
    el.textContent = message;
    $("toasts").appendChild(el);
    setTimeout(function () { el.remove(); }, 6000);
  }

  function api(path, options) {
    return fetch(path, options).then(function (response) {
      return response.json().catch(function () { return {}; })
        .then(function (body) {
          if (!response.ok) {
            throw new Error(body.error || ("HTTP " + response.status));
          }
          return body;
        });
    });
  }

  /* ------------------------------------------------------- step 1: build
   *
   * A build takes a minute or two, far too long to hold a request open, so the
   * server runs it on a thread and this polls. The version typed here is
   * written into app_config.h and compiled in, which is what makes it the same
   * number the device will report after the update.
   */

  var buildPoll = null;

  function renderBuild(state) {
    var out = $("build-out");
    if (!out) { return; }

    if (state.running) {
      var stages = (state.stages || []).map(function (s) {
        return "<li class=\"" + (s.ok ? "" : "no") + "\">" + esc(s.label)
          + "</li>";
      }).join("");
      out.innerHTML = "<div class=\"panel\"><b class=\"head\">"
        + "<span class=\"spin\"></span> Building " + esc(state.version)
        + "…</b><ul class=\"stages\">" + stages + "</ul>"
        + "<p class=\"hint\">First build after a version change takes a minute "
        + "or two. You can leave this page open.</p></div>";
      return;
    }

    if (state.ok === null || state.ok === undefined) { return; }

    if (state.ok) {
      out.innerHTML = "<div class=\"panel ok\"><b class=\"head\">"
        + "Built firmware " + esc(state.version) + " (security "
        + esc(state.security_version) + ")</b>"
        + "<dl class=\"facts\"><dt>Image</dt><dd class=\"mono\">"
        + esc(state.artifact) + "</dd></dl>"
        + "<p>It is selected in step 3 below — the version fields are "
        + "filled in to match what was compiled.</p></div>";
    } else {
      out.innerHTML = "<div class=\"panel bad\"><b class=\"head\">"
        + "Build failed</b>" + esc(state.error || "see the log")
        + (state.log ? "<pre><code>"
           + esc(state.log.split("\n").slice(-25).join("\n"))
           + "</code></pre>" : "") + "</div>";
    }
  }

  function pollBuild() {
    api("/api/firmware/build").then(function (state) {
      renderBuild(state);
      if (state.running) { return; }

      clearInterval(buildPoll);
      buildPoll = null;
      $("btn-build").disabled = false;
      $("btn-build").textContent = "Build firmware";

      if (state.ok) {
        toast("Built " + state.version, "ok");
        // Carry the numbers forward so the package cannot disagree with the
        // image: this mismatch is the classic way an update "succeeds" and
        // then reports the old version.
        $("pkg-version").value = state.version;
        $("pkg-security").value = state.security_version;
        refresh(state.artifact);
      } else {
        toast(state.error || "Build failed", "bad");
      }
    }).catch(function () { /* transient; the next tick retries */ });
  }

  function startBuild(event) {
    event.preventDefault();
    var button = $("btn-build");
    button.disabled = true;
    button.textContent = "Building…";

    api("/api/firmware/build", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version: $("build-version").value.trim(),
        security_version: Number($("build-security").value)
      })
    }).then(function (state) {
      renderBuild(state);
      if (!buildPoll) { buildPoll = setInterval(pollBuild, 2000); }
    }).catch(function (error) {
      button.disabled = false;
      button.textContent = "Build firmware";
      $("build-out").innerHTML = "<div class=\"panel bad\">"
        + "<b class=\"head\">Cannot start the build</b>"
        + esc(error.message) + "</div>";
      toast(error.message, "bad");
    });
  }

  function initBuild() {
    if (!$("build-form")) { return; }
    $("build-form").addEventListener("submit", startBuild);

    api("/api/firmware/build").then(function (state) {
      if (!state.available) {
        $("build-note").textContent = state.note;
        $("btn-build").disabled = true;
        return;
      }
      $("build-note").textContent = "";
      renderBuild(state);
      if (state.running) {
        $("btn-build").disabled = true;
        $("btn-build").textContent = "Building…";
        buildPoll = setInterval(pollBuild, 2000);
      }
    }).catch(function () { /* the page still works without this step */ });
  }

  /* ------------------------------------------------------- step 2: upload */

  var chosen = null;

  function showChosen(file) {
    chosen = file;
    $("drop").classList.toggle("chosen", !!file);
    $("drop-main").textContent = file
      ? file.name + "  (" + bytes(file.size) + ")"
      : "Choose a .bin file, or drag one here";
    $("btn-upload").disabled = !file;
  }

  function imageFacts(image) {
    var rows = [
      ["Looks like", image.verdict || "—"],
      ["Chip", image.chip],
      ["Project name", image.app_name],
      ["App version", image.app_version],
      ["Built with", image.idf_version],
      ["Compiled", image.compiled],
      ["First byte", image.first_byte]
    ].filter(function (pair) { return pair[1]; });

    return "<dl class=\"facts\">" + rows.map(function (pair) {
      return "<dt>" + esc(pair[0]) + "</dt><dd>" + esc(pair[1]) + "</dd>";
    }).join("") + "</dl>";
  }

  function renderUpload(result) {
    var image = result.image || {};
    var good = image.magic_ok;
    var head;

    if (result.duplicate) {
      head = "Already uploaded — reusing " + result.file;
    } else if (good) {
      head = "Uploaded and checked: " + result.file;
    } else {
      head = "Stored, but this does not look like an ESP32 image";
    }

    var extra = "";
    if (result.renamed && result.original_name) {
      extra += "<p>Stored as <code>" + esc(result.file) + "</code> — your "
        + "name <code>" + esc(result.original_name) + "</code> contained "
        + "characters that are not allowed in a stored file name.</p>";
    }
    if (result.note) {
      extra += "<p>" + esc(result.note) + "</p>";
    }
    if (!good) {
      extra += "<p>It was kept so you can package it anyway, but a device "
        + "would refuse to boot it. Check you picked "
        + "<code>build/secure_ota.bin</code>.</p>";
    }

    $("upload-out").innerHTML =
      "<div class=\"panel " + (good ? "ok" : "warn") + "\">"
      + "<b class=\"head\">" + esc(head) + "</b>"
      + "<dl class=\"facts\">"
      + "<dt>Size</dt><dd>" + bytes(result.size) + "</dd>"
      + "<dt>SHA-256</dt><dd class=\"mono\">" + esc(result.sha256 || "") + "</dd>"
      + "</dl>" + imageFacts(image) + extra + "</div>";
  }

  function upload(event) {
    event.preventDefault();
    if (!chosen) { return; }

    var data = new FormData();
    data.append("file", chosen);
    $("btn-upload").disabled = true;
    $("btn-upload").textContent = "Uploading…";
    $("upload-out").innerHTML = "";

    api("/api/firmware/upload", { method: "POST", body: data })
      .then(function (result) {
        renderUpload(result);
        toast(result.duplicate ? "Already had those bytes" : "Upload accepted",
              "ok");
        return refresh(result.file);
      })
      .catch(function (error) {
        $("upload-out").innerHTML =
          "<div class=\"panel bad\"><b class=\"head\">Upload refused</b>"
          + esc(error.message) + "</div>";
        toast(error.message, "bad");
      })
      .then(function () {
        $("btn-upload").textContent = "Upload";
        $("btn-upload").disabled = !chosen;
      });
  }

  /* ------------------------------------------------------------ step 2 */

  function renderStages(result) {
    var stages = (result.stages || []).map(function (stage) {
      return "<li class=\"" + (stage.ok ? "" : "no") + "\">"
        + esc(stage.label) + "</li>";
    }).join("");

    var facts = [
      ["Package", result.filename],
      ["Ascon-Hash256", result.firmware_hash],
      ["Ascon nonce", result.nonce],
      ["Ascon tag", result.auth_tag],
      ["Ed25519 signature", result.signature],
      ["Took", result.duration_ms ? result.duration_ms + " ms" : ""]
    ].filter(function (pair) { return pair[1]; })
      .map(function (pair) {
        return "<dt>" + esc(pair[0]) + "</dt><dd class=\"mono\">"
          + esc(pair[1]) + "</dd>";
      }).join("");

    $("pkg-out").innerHTML =
      "<div class=\"panel ok\"><b class=\"head\">Package created and "
      + "self-verified</b><ul class=\"stages\">" + stages + "</ul>"
      + "<dl class=\"facts\">" + facts + "</dl>"
      + "<p>It is staged, so devices are not offered it yet. Publish it in "
      + "step 3 below.</p></div>";
  }

  function makePackage(event) {
    event.preventDefault();
    var source = $("pkg-source").value;
    if (!source) {
      toast("Upload a .bin first", "bad");
      return;
    }

    var button = $("btn-package");
    button.disabled = true;
    button.textContent = "Signing and encrypting…";
    $("pkg-out").innerHTML = "";

    api("/api/firmware/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file: source,
        version: $("pkg-version").value.trim(),
        security_version: Number($("pkg-security").value)
      })
    })
      .then(function (result) {
        renderStages(result);
        toast("Package ready: " + result.filename, "ok");
        return refresh();
      })
      .catch(function (error) {
        $("pkg-out").innerHTML =
          "<div class=\"panel bad\"><b class=\"head\">Could not create the "
          + "package</b>" + esc(error.message) + "</div>";
        toast(error.message, "bad");
      })
      .then(function () {
        button.disabled = false;
        button.textContent = "Create secure package";
      });
  }

  /* ------------------------------------------------------------ step 3 */

  function act(path, label) {
    api(path, { method: "POST" })
      .then(function () { toast(label, "ok"); return refresh(); })
      .catch(function (error) { toast(error.message, "bad"); });
  }

  /* The file name comes from disk, so it is never interpolated into markup
   * that the browser will execute. It rides on a data attribute and is read
   * back here. */
  $("pkg-body").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-act]");
    if (!button) { return; }
    var name = button.getAttribute("data-file");
    if (button.getAttribute("data-act") === "publish") {
      act("/api/firmware/" + encodeURIComponent(name) + "/publish",
          name + " is now offered to devices");
    } else {
      act("/api/firmware/" + encodeURIComponent(name) + "/unpublish",
          name + " withdrawn");
    }
  });

  function renderPackages(packages) {
    if (!packages.length) {
      $("pkg-body").innerHTML =
        "<tr><td colspan=\"6\" class=\"empty\">No packages yet — "
        + "finish steps 1 and 2.</td></tr>";
      return;
    }

    $("pkg-body").innerHTML = packages.map(function (row) {
      var status, action;
      if (!row.valid) {
        status = "<span class=\"tag bad\">unreadable</span>";
        action = "";
      } else if (row.published) {
        status = "<span class=\"tag ok\">published</span>";
        action = "<button class=\"btn small quiet\" data-act=\"unpublish\" "
          + "data-file=\"" + esc(row.file) + "\">Withdraw</button>";
      } else {
        status = "<span class=\"tag dim\">staged</span>";
        action = "<button class=\"btn small\" data-act=\"publish\" "
          + "data-file=\"" + esc(row.file) + "\">Publish</button>";
      }

      return "<tr><td class=\"mono\">" + esc(row.file) + "</td>"
        + "<td>" + esc(row.firmware_version || "—") + "</td>"
        + "<td>" + esc(row.security_version === undefined
                       ? "—" : row.security_version) + "</td>"
        + "<td>" + bytes(row.package_size) + "</td>"
        + "<td>" + status + "</td>"
        + "<td>" + action + "</td></tr>";
    }).join("");
  }

  /* ------------------------------------------------------- uploaded files */

  function renderUploads(rows, select) {
    if (!rows.length) {
      $("up-body").innerHTML =
        "<tr><td colspan=\"5\" class=\"empty\">Nothing uploaded yet.</td></tr>";
      $("pkg-source").innerHTML =
        "<option value=\"\">upload a .bin first</option>";
      return;
    }

    $("up-body").innerHTML = rows.map(function (row) {
      var what;
      if (row.looks_like_esp32_image === true) {
        what = "<span class=\"tag ok\">ESP32 image</span>";
        if (row.app_name) { what += " " + esc(row.app_name); }
        if (row.app_version) { what += " <span class=\"mono\">" + esc(row.app_version) + "</span>"; }
      } else if (row.looks_like_esp32_image === false) {
        what = "<span class=\"tag warn\">not an ESP32 image</span>";
      } else {
        what = "<span class=\"tag dim\">not inspected</span>";
      }

      return "<tr><td class=\"mono\">" + esc(row.file) + "</td>"
        + "<td>" + bytes(row.size) + "</td>"
        + "<td class=\"mono\">" + esc((row.sha256 || "—").slice(0, 16))
        + (row.sha256 ? "…" : "") + "</td>"
        + "<td>" + what + "</td>"
        + "<td>" + esc(when(row.modified)) + "</td></tr>";
    }).join("");

    // The project name goes in the option text on purpose. Two images of the
    // same size from different projects look identical by file name, and
    // signing the wrong one produces a package that installs perfectly and
    // bricks the device's ability to be updated again.
    var keep = select || $("pkg-source").value;
    $("pkg-source").innerHTML = rows.map(function (row) {
      var what = row.app_name
        ? row.app_name + (row.app_version ? " " + row.app_version : "")
        : (row.looks_like_esp32_image === false ? "not an ESP32 image"
                                                : "unknown project");
      return "<option value=\"" + esc(row.file) + "\">" + esc(row.file)
        + " — " + esc(what) + " — " + bytes(row.size) + "</option>";
    }).join("");
    if (keep) { $("pkg-source").value = keep; }
  }

  /* ------------------------------------------------- what is happening now
   *
   * Everything below is the device's own report. When it has not said
   * something, this shows a dash rather than inventing it -- a progress bar
   * that moves on its own would be a lie about a device that may be dead.
   */

  function renderStatus(summary) {
    var chip = $("status-chip");
    var device = summary.device;
    if (!device) {
      chip.className = "status";
      chip.textContent = "server up · no device seen yet";
    } else {
      var online = device.status === "ONLINE" || device.status === "REBOOTING";
      chip.className = "status " + (online ? "online" : "offline");
      chip.textContent = device.device_id + " · "
        + String(device.status || "unknown").toLowerCase()
        + (device.firmware_version ? " · v" + device.firmware_version : "");
    }
    // The live panel is optional: a browser holding a cached copy of an older
    // page will not have these elements, and a missing box must not take the
    // rest of the page down with it.
    if (!$("live-device")) { return; }
    if ($("live-timeout") && summary.server) {
      $("live-timeout").textContent = summary.server.heartbeat_timeout_s;
    }
    renderDevice(summary);
    renderProgress(device);
    renderPipeline(summary.pipeline || []);
    renderEvents(summary.history || []);
  }

  /* When the last successful poll was. A panel that has stopped updating must
   * say so: the worst failure this page can have is showing a confident
   * ONLINE that was true a minute ago and is not true now. */
  var lastOk = 0;

  function markStale() {
    if (!lastOk || !$("live")) { return; }
    var age = Math.round((Date.now() - lastOk) / 1000);
    var stale = age > 20;
    $("live").classList.toggle("stale", stale);
    var note = $("live-fresh");
    if (note) {
      note.textContent = stale
        ? "This page has not reached the server for " + age
          + "s — everything below is that old, not live."
        : "updated " + age + "s ago";
      note.className = "fresh" + (stale ? " bad" : "");
    }
  }

  function renderDevice(summary) {
    var d = summary.device;
    if (!d) {
      $("live-device").innerHTML =
        "<span class=\"muted\">No device has reported in yet. Once the ESP32 "
        + "boots and joins Wi-Fi it appears here within a few seconds.</span>";
      return;
    }

    var word = { ONLINE: "ok", REBOOTING: "warn", OFFLINE: "bad" }[d.status]
      || "dim";
    var head = "<span class=\"tag " + word + "\">" + esc(d.status) + "</span> "
      + "<b>" + esc(d.device_id) + "</b> is running firmware <b>"
      + esc(d.firmware_version || "?") + "</b> (security "
      + esc(d.security_version === null ? "?" : d.security_version) + ")"
      + (d.partition ? " from <b>" + esc(d.partition) + "</b>" : "") + ".";

    var update = summary.update;
    if (update) {
      head += " An update to <b>" + esc(update.available) + "</b> is published "
        + "and waiting — the device takes it on its next check.";
    } else if (d.status === "ONLINE") {
      head += " It is up to date.";
    }

    var meta = [
      ["IP", d.ip],
      ["Wi-Fi", d.wifi_ssid ? d.wifi_ssid + " (" + d.wifi_rssi + " dBm)" : ""],
      ["Free heap", d.free_heap ? d.free_heap.toLocaleString() + " B" : ""],
      ["Uptime", d.uptime_s ? Math.floor(d.uptime_s / 60) + "m "
        + (d.uptime_s % 60) + "s" : ""],
      ["Checks", d.ota_checks],
      ["Rejections", d.ota_rejections],
      ["Last heartbeat", d.seconds_since_heartbeat === null ? ""
        : d.seconds_since_heartbeat + "s ago"]
    ].filter(function (p) {
      return p[1] !== "" && p[1] !== null && p[1] !== undefined;
    });

    $("live-device").innerHTML = head + "<div class=\"device-meta\">"
      + meta.map(function (p) {
        return "<span>" + esc(p[0]) + ": " + esc(p[1]) + "</span>";
      }).join("") + "</div>";
  }

  function renderProgress(device) {
    var wrap = $("live-progress");
    var total = device && device.ota_total;
    var done = (device && device.ota_done) || 0;
    var state = (device && device.ota_state) || "IDLE";

    if (!device || state === "IDLE" || !total) {
      wrap.classList.add("hidden");
      return;
    }
    wrap.classList.remove("hidden");
    var pct = Math.min(100, Math.round((done / total) * 100));
    $("live-stage").textContent = "Update in progress — " + state;
    $("live-bytes").textContent = done.toLocaleString() + " / "
      + total.toLocaleString() + " bytes (" + pct + "%)";
    $("live-bar").style.width = pct + "%";
  }

  function renderPipeline(stages) {
    $("live-pipeline").innerHTML = stages.map(function (s) {
      return "<li class=\"" + esc(s.state) + "\">" + esc(s.label) + "</li>";
    }).join("");
  }

  function renderEvents(events) {
    if (!events.length) {
      $("live-events").innerHTML =
        "<li class=\"muted\">Nothing recorded yet.</li>";
      return;
    }
    $("live-events").innerHTML = events.slice(0, 6).map(function (e) {
      var bad = e.result === "REJECTED" || e.result === "FAILED";
      var when = new Date(e.ts * 1000).toLocaleTimeString();
      return "<li><time>" + esc(when) + "</time>"
        + "<span>" + esc(e.event) + (e.stage ? " · " + esc(e.stage) : "")
        + "</span>"
        + "<span class=\"res " + (bad ? "bad" : "ok") + "\">"
        + esc(e.result) + "</span>"
        + (e.to_version ? "<span class=\"mono\">" + esc(e.to_version)
                          + "</span>" : "")
        + (e.reason ? "<span class=\"muted\">" + esc(e.reason) + "</span>" : "")
        + "</li>";
    }).join("");
  }

  /* ---------------------------------------------------------- attack lab
   *
   * The server runs the project's real tamper/verify tools and hands back what
   * they printed. This parses the verifier's stage lines so you can see which
   * check caught the attack, rather than only a green or red word.
   */

  var STAGE_RE = /^\s*\[(\d+)\]\s+(.+?)\s{2,}(PASS|FAIL)\s*(.*)$/;

  function parseStages(output) {
    return String(output || "").split("\n").reduce(function (acc, line) {
      var m = STAGE_RE.exec(line);
      if (m) {
        acc.push({ n: m[1], name: m[2].trim(), verdict: m[3],
                   detail: m[4].trim() });
      }
      return acc;
    }, []);
  }

  function labCard(test) {
    return "<div class=\"lab-card\" id=\"lab-" + esc(test.key) + "\">"
      + "<div class=\"lab-head\">"
      + "<span class=\"lab-name\">" + esc(test.label) + "</span>"
      + "<span class=\"lab-mode\">" + esc(test.mode) + "</span>"
      + "<span class=\"tag dim\" data-role=\"status\">not run</span>"
      + "<button class=\"btn small\" data-test=\"" + esc(test.key)
      + "\">Run</button>"
      + "</div>"
      + "<div class=\"lab-why\">should be stopped by: <b>"
      + esc(test.defended_by) + "</b></div>"
      + "<div data-role=\"out\"></div>"
      + "</div>";
  }

  function renderLabResult(key, result) {
    var card = $("lab-" + key);
    if (!card) { return; }
    var good = result.passed;
    card.className = "lab-card " + (good ? "ok" : "bad");

    var pill = card.querySelector("[data-role=status]");
    pill.className = "tag " + (good ? "ok" : "bad");
    pill.textContent = result.status;

    var stages = parseStages(result.output).map(function (s) {
      return "<li><span class=\"n\">" + esc(s.n) + "</span>"
        + "<span class=\"nm\">" + esc(s.name) + "</span>"
        + "<span class=\"vd " + s.verdict.toLowerCase() + "\">"
        + esc(s.verdict) + "</span>"
        + "<span class=\"dt\">" + esc(s.detail) + "</span></li>";
    }).join("");

    card.querySelector("[data-role=out]").innerHTML =
      "<div class=\"lab-result " + (good ? "ok" : "bad") + "\">"
      + esc(result.headline) + "</div>"
      + (stages ? "<ul class=\"lab-stages\">" + stages + "</ul>" : "")
      + "<div class=\"lab-base\">" + esc(result.result_line) + " · "
      + esc(result.base_note) + " · " + esc(result.duration_ms)
      + " ms</div>";
  }

  function runLabTest(key) {
    var card = $("lab-" + key);
    if (!card) { return Promise.resolve(); }
    card.className = "lab-card busy";
    var pill = card.querySelector("[data-role=status]");
    pill.className = "tag dim";
    pill.innerHTML = "<span class=\"spin\"></span> running";
    card.querySelector("[data-role=out]").innerHTML = "";

    var real = $("lab-real") && $("lab-real").checked;
    return api("/api/security/lab/" + encodeURIComponent(key)
               + (real ? "?base=published" : ""), { method: "POST" })
      .then(function (result) { renderLabResult(key, result); })
      .catch(function (error) {
        card.className = "lab-card bad";
        pill.className = "tag bad";
        pill.textContent = "error";
        card.querySelector("[data-role=out]").innerHTML =
          "<div class=\"lab-result bad\">" + esc(error.message) + "</div>";
      });
  }

  function loadLab() {
    if (!$("lab-grid")) { return; }
    api("/api/security/lab").then(function (data) {
      $("lab-grid").innerHTML = data.tests.map(labCard).join("");
      if (!data.keys_present) {
        $("lab-note").textContent =
          "keys/ is incomplete -- run: python tools/generate_keys.py";
        $("lab-run-all").disabled = true;
      }
    }).catch(function (error) {
      $("lab-grid").innerHTML =
        "<p class=\"hint\">Could not load the tests: " + esc(error.message)
        + "</p>";
    });

    $("lab-grid").addEventListener("click", function (event) {
      var button = event.target.closest("button[data-test]");
      if (button) { runLabTest(button.getAttribute("data-test")); }
    });

    $("lab-run-all").addEventListener("click", function () {
      var buttons = Array.prototype.slice.call(
        $("lab-grid").querySelectorAll("button[data-test]"));
      var all = $("lab-run-all");
      all.disabled = true;
      all.textContent = "Running…";
      // Sequential: each test shells out to the packaging tools, and running
      // nine of those at once would only make every one of them slower.
      buttons.reduce(function (chain, button) {
        return chain.then(function () {
          return runLabTest(button.getAttribute("data-test"));
        });
      }, Promise.resolve()).then(function () {
        all.disabled = false;
        all.textContent = "Run all tests";
        toast("All attack tests finished", "ok");
      });
    });
  }

  /* -------------------------------------------------------------- refresh */

  function refresh(selectFile) {
    return api("/api/firmware").then(function (data) {
      renderUploads(data.uploads || [], selectFile);
      renderPackages(data.packages || []);
      $("keys-note").textContent = data.keys_present ? "" : data.keys_note || "";
      $("btn-package").disabled = !data.keys_present;
    }).catch(function (error) {
      toast("Could not read the firmware list: " + error.message, "bad");
    });
  }

  /* Poll faster while an update is actually moving, so the bar tracks the
   * device instead of lagging a heartbeat behind it. */
  var statusTimer = null;
  var pollMs = 0;

  function schedule(ms) {
    if (ms === pollMs) { return; }
    pollMs = ms;
    clearInterval(statusTimer);
    statusTimer = setInterval(refreshStatus, ms);
  }

  function refreshStatus() {
    api("/api/dashboard/summary").catch(function (error) {
      // The request itself failed. This is the only case that is honestly
      // "unreachable" -- a bug in the rendering below is not.
      $("status-chip").className = "status offline";
      $("status-chip").textContent = "server unreachable";
      schedule(8000);
      throw error;
    }).then(function (summary) {
      try {
        lastOk = Date.now();
        renderStatus(summary);
        markStale();
      } catch (error) {
        $("status-chip").className = "status offline";
        $("status-chip").textContent = "page out of date — press Ctrl+F5";
        console.error("Secure OTA: cannot render the status panel", error);
      }
      var device = summary.device;
      var busy = device && device.ota_state && device.ota_state !== "IDLE";
      schedule(busy ? 1500 : 8000);
      // An update that just finished changes what is published.
      if (busy && device.ota_state === "REBOOT") { refresh(); }
    }).catch(function () { /* already reported above */ });
  }

  /* ----------------------------------------------------------------- wire */

  var drop = $("drop");

  ["dragenter", "dragover"].forEach(function (name) {
    drop.addEventListener(name, function (event) {
      event.preventDefault();
      drop.classList.add("over");
    });
  });

  ["dragleave", "drop"].forEach(function (name) {
    drop.addEventListener(name, function (event) {
      event.preventDefault();
      drop.classList.remove("over");
    });
  });

  drop.addEventListener("drop", function (event) {
    var files = event.dataTransfer && event.dataTransfer.files;
    if (files && files.length) { showChosen(files[0]); }
  });

  $("bin-file").addEventListener("change", function (event) {
    showChosen(event.target.files[0] || null);
  });

  $("upload-form").addEventListener("submit", upload);
  $("pkg-form").addEventListener("submit", makePackage);

  refresh();
  refreshStatus();
  loadLab();
  initBuild();
  // Independent of the poll: if polling itself dies, this is what notices.
  setInterval(markStale, 1000);
}());
