(function () {
  var DATA_URL = 'data/index.json';

  function spfBadge(hasSPF) {
    return '<span class="spf-badge ' + (hasSPF ? 'badge-ok">SPF ✓' : 'badge-fail">SPF ✗') + '</span>';
  }

  function dmarcBadge(policy, hasDMARC) {
    if (!hasDMARC) return '<span class="dmarc-badge badge-fail">NO DMARC</span>';
    var cls = policy === 'reject' ? 'badge-ok' : policy === 'quarantine' ? 'badge-warn' : 'badge-fail';
    return '<span class="dmarc-badge ' + cls + '">p=' + (policy || 'none') + '</span>';
  }

  function renderCard(entry) {
    var card = document.createElement('div');
    card.className = 'domain-card';
    card.setAttribute('data-domain', entry.domain);

    var spoofHtml = entry.spoofable
      ? '<span class="spoofable-yes">⚠ SPOOFABLE</span>'
      : '<span class="spoofable-no">✓ PROTECTED</span>';

    card.innerHTML =
      '<div class="card-header-row">' +
        '<span class="card-domain">' + entry.domain + '</span>' +
        '<span class="card-date">' + (entry.last_refreshed || entry.queried_at || '').slice(0, 10) + '</span>' +
      '</div>' +
      '<div class="card-stats">' +
        '<span class="card-stat">' + (entry.a_count || 0) + ' A</span>' +
        '<span class="card-stat">' + (entry.mx_count || 0) + ' MX</span>' +
        '<span class="card-stat">' + (entry.ns_count || 0) + ' NS</span>' +
        '<span class="card-stat">' + (entry.txt_count || 0) + ' TXT</span>' +
        spfBadge(entry.has_spf) +
        dmarcBadge(entry.dmarc_policy, entry.has_dmarc) +
        '  ' + spoofHtml +
      '</div>' +
      '<div class="card-contributor">' +
        '<span class="card-name">' + (entry.display_name || '') + '</span>' +
        '<span>' + (entry.display_loc || '') + '</span>' +
      '</div>';

    card.addEventListener('click', function () {
      window.location.href = 'domain.html?d=' + encodeURIComponent(entry.domain);
    });
    return card;
  }

  function render(domains) {
    var list = document.getElementById('domain-list');
    if (!list) return;
    list.innerHTML = '';
    if (!domains.length) { list.innerHTML = '<p class="empty">No results.</p>'; return; }
    domains.forEach(function (e) { list.appendChild(renderCard(e)); });
  }

  function applySearch(all) {
    var input = document.getElementById('search-input');
    if (!input) return;
    input.addEventListener('input', function () {
      var q = input.value.trim().toLowerCase();
      render(!q ? all : all.filter(function (e) {
        return e.domain.toLowerCase().includes(q);
      }));
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    fetch(DATA_URL)
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (data) {
        var domains = (data.domains || []).slice().sort(function (a, b) {
          return a.domain.localeCompare(b.domain);
        });

        var statsEl = document.getElementById('db-stats');
        if (statsEl) {
          var withSPF   = domains.filter(function (d) { return d.has_spf; }).length;
          var withDMARC = domains.filter(function (d) { return d.has_dmarc; }).length;
          statsEl.textContent = domains.length + ' domain' + (domains.length !== 1 ? 's' : '') +
            ' · ' + withSPF + ' with SPF · ' + withDMARC + ' with DMARC';
        }

        render(domains);
        applySearch(domains);
      })
      .catch(function (err) {
        var list = document.getElementById('domain-list');
        if (list) list.innerHTML = '<p class="empty">Failed to load: ' + err.message + '</p>';
      });
  });
})();
