/* shop-ui.js - shared storefront UI: cart (sessionStorage), auth state, money, header. */
(function (global) {
  'use strict';
  var CART = 'pico_cart';
  function money(c) { return '$' + (c / 100).toFixed(2); }
  function getCart() { try { return JSON.parse(sessionStorage.getItem(CART)) || []; } catch (_) { return []; } }
  function setCart(c) { try { sessionStorage.setItem(CART, JSON.stringify(c)); } catch (_) {} renderCount(); }
  function addToCart(item) { var c = getCart(); var ex = c.find(function (x) { return x.id === item.id; });
    if (ex) ex.qty += item.qty || 1; else c.push({ id: item.id, name: item.name, price: item.price, qty: item.qty || 1 });
    setCart(c); }
  function clearCart() { setCart([]); }
  function cartCount() { return getCart().reduce(function (s, x) { return s + x.qty; }, 0); }
  function renderCount() { var el = document.getElementById('cart-count'); if (el) el.textContent = cartCount(); }

  function me() { return fetch('/api/me').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }); }
  function renderHeader() {
    renderCount();
    me().then(function (m) {
      var el = document.getElementById('auth-slot'); if (!el) return;
      if (m && m.user) el.innerHTML = '<span class="pill">' + m.user.displayName + '</span> ' +
        '<a href="#" id="logout">Sign out</a>';
      else el.innerHTML = '<a href="/#signin">Partner sign-in</a>';
      var lo = document.getElementById('logout');
      if (lo) lo.onclick = function (e) { e.preventDefault(); fetch('/api/logout', { method: 'POST' }).then(function () { location.href = '/'; }); };
    });
  }
  function header(active) {
    return '<header class="site"><div class="wrap">' +
      '<a class="logo" href="/"><span class="dot"></span>Pico Mobile <span class="hdr-tag">PARTNERS</span></a>' +
      '<nav class="main">' +
      '<a href="/catalog"' + (active === 'catalog' ? ' style="color:var(--ink)"' : '') + '>Catalog</a>' +
      '<a href="/#how">How it works</a>' +
      '<a href="/contact"' + (active === 'support' ? ' style="color:var(--ink)"' : '') + '>Support</a></nav>' +
      '<div class="spacer"></div>' +
      '<div class="hdr-right"><a href="/cart">Order <span class="pill" id="cart-count">0</span></a>' +
      '<span id="auth-slot"><a href="/#signin">Partner sign-in</a></span></div>' +
      '</div></header>';
  }
  function footer() {
    return '<footer class="site"><div class="wrap">' +
      '&copy; 2026 Pico Mobile · Partner portal, access by invitation &nbsp;|&nbsp; ' +
      '<a href="/contact">Partner support</a> &nbsp;|&nbsp; Privacy &nbsp;|&nbsp; Terms of supply' +
      '<div style="margin-top:8px;font-size:12px">Pico Mobile is an independent reseller of refurbished devices and is not affiliated with Apple, Samsung, Google, OnePlus or Motorola. Product names are trademarks of their respective owners.</div>' +
      '</div></footer>';
  }
  global.Shop = { money: money, getCart: getCart, setCart: setCart, addToCart: addToCart, clearCart: clearCart,
                  cartCount: cartCount, me: me, renderHeader: renderHeader, header: header, footer: footer };
})(window);
