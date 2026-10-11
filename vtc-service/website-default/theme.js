// Colour theme for the home page: Match system / Light / Dark.
//
// The static twin of the console's and member portal's switcher
// (`admin-ui/src/components/ThemeSwitcher.tsx`, `admin-ui/src/lib/theme.ts`),
// sharing their localStorage key, so one choice holds on all three of the
// community's surfaces. "Match system" stores nothing: the page then follows
// `prefers-color-scheme` through `color-scheme: light dark` in tokens.css.
//
// Loaded in <head> without `defer` so the pinned theme lands before first
// paint (an inline script would be refused by the page's `default-src 'self'`).
// The switcher's markup is in index.html, `hidden` until this wires it up, so
// a browser without JavaScript simply follows the system.

(function () {
  var KEY = "vtc-admin-theme";
  var PREFS = ["auto", "light", "dark"];

  function stored() {
    try {
      var v = window.localStorage.getItem(KEY);
      return v === "light" || v === "dark" ? v : "auto";
    } catch (e) {
      return "auto";
    }
  }

  function apply(pref) {
    var root = document.documentElement;
    if (pref === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", pref);
  }

  function save(pref) {
    try {
      if (pref === "auto") window.localStorage.removeItem(KEY);
      else window.localStorage.setItem(KEY, pref);
    } catch (e) {
      /* Blocked storage: the choice holds for this page view only. */
    }
  }

  apply(stored());

  function wire() {
    var group = document.getElementById("theme-switcher");
    if (!group) return;
    var buttons = Array.prototype.slice.call(group.querySelectorAll("[data-theme-choice]"));

    function show(pref) {
      buttons.forEach(function (b) {
        var on = b.getAttribute("data-theme-choice") === pref;
        b.setAttribute("aria-checked", on ? "true" : "false");
        b.tabIndex = on ? 0 : -1;
      });
    }

    function choose(pref, focus) {
      save(pref);
      apply(pref);
      show(pref);
      if (focus) {
        var b = group.querySelector('[data-theme-choice="' + pref + '"]');
        if (b) b.focus();
      }
    }

    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        choose(b.getAttribute("data-theme-choice"), false);
      });
      b.addEventListener("keydown", function (e) {
        var i = PREFS.indexOf(b.getAttribute("data-theme-choice"));
        var next = null;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") next = (i + 1) % PREFS.length;
        else if (e.key === "ArrowLeft" || e.key === "ArrowUp")
          next = (i + PREFS.length - 1) % PREFS.length;
        else if (e.key === "Home") next = 0;
        else if (e.key === "End") next = PREFS.length - 1;
        if (next === null) return;
        e.preventDefault();
        choose(PREFS[next], true);
      });
    });

    // A choice made in another tab (the console, the portal) follows here.
    window.addEventListener("storage", function (e) {
      if (e.key !== KEY && e.key !== null) return;
      var pref = stored();
      apply(pref);
      show(pref);
    });

    show(stored());
    group.hidden = false;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
