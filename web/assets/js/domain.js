(function () {
  function param(name) {
    return new URLSearchParams(window.location.search).get(name);
  }
  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val != null ? String(val) : '—';
  }

  function addESRow(grid, key, val, extraClass) {
    if (!grid) return;
    var row = document.createElement('div');
    row.className = 'es-row';
    var valClass = 'es-val' + (extraClass ? ' ' + extraClass : '');
    row.innerHTML = '<span class="es-key">' + key + '</span>' +
      '<span class="' + valClass + '">' + (val != null && val !== '' ? val : '—') + '</span>';
    grid.appendChild(row);
  }

  function renderRecords(container, records) {
    if (!container) return;
    var types = [
      {key: 'a',      label: 'A',       color: 'green'},
      {key: 'aaaa',   label: 'AAAA',    color: null},
      {key: 'ns',     label: 'NS',      color: null},
      {key: 'mx',     label: 'MX',      color: null},
      {key: 'txt',    label: 'TXT',     color: null},
      {key: 'soa',    label: 'SOA',     color: null},
      {key: 'caa',    label: 'CAA',     color: null},
    ];

    types.forEach(function (t) {
      var vals = records[t.key];
      if (!vals) return;
      // Normalise: soa may be a string, others arrays
      var arr = Array.isArray(vals) ? vals : (vals ? [vals] : []);
      if (!arr.length) return;

      var sec = document.createElement('div');
      sec.className = 'record-section';
      sec.innerHTML = '<div class="record-title">' + t.label + '</div>';
      var list = document.createElement('div');
      list.className = 'record-list';
      arr.forEach(function (v) {
        var item = document.createElement('div');
        item.className = 'record-item';
        item.innerHTML = '<span class="record-value">' + v + '</span>';
        list.appendChild(item);
      });
      sec.appendChild(list);
      container.appendChild(sec);
    });

    // DNSKEY / DNSSEC
    var dnskeySec = document.createElement('div');
    dnskeySec.className = 'record-section';
    dnskeySec.innerHTML = '<div class="record-title">DNSKEY / DNSSEC</div>' +
      '<div class="record-list"><div class="record-item"><span class="record-value">' +
      (records.dnskey ? 'DNSKEY present — DNSSEC deployed' : 'NODATA — DNSSEC not deployed') +
      '</span></div></div>';
    container.appendChild(dnskeySec);
  }

  document.addEventListener('DOMContentLoaded', function () {
    var domain = param('d');
    if (!domain) { window.location.href = 'dns-board.html'; return; }

    fetch('data/domains/' + domain + '.json')
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        setText('domain-name-display', d.domain);
        var contribEl = document.getElementById('contributor-meta');
        if (contribEl && d.display_name) {
          contribEl.textContent = d.display_name + (d.display_loc ? ' · ' + d.display_loc : '');
        }

        // Stat badges
        var rec = d.records || {};
        setText('val-a-count',        (rec.a || []).length);
        setText('val-mx-count',       (rec.mx || []).length);
        setText('val-subdomain-count', d.subdomain_count || 0);

        var spoofEl = document.getElementById('val-spoofable');
        if (spoofEl) {
          spoofEl.textContent = d.email_spoofable ? 'YES' : 'NO';
          spoofEl.style.color = d.email_spoofable ? 'var(--red)' : 'var(--green)';
        }

        setText('queried-at', (d.queried_at || '').slice(0, 10));

        // DNS Records
        renderRecords(document.getElementById('records-grid'), rec);

        // Email Security
        var emailGrid = document.getElementById('email-grid');
        var spf   = d.spf   || {};
        var dmarc = d.dmarc || {};
        addESRow(emailGrid, 'SPF Raw',         spf.raw   || 'Not found');
        addESRow(emailGrid, 'SPF Qualifier',   spf.all   || '—');
        addESRow(emailGrid, 'DMARC Raw',       dmarc.raw || 'Not found');
        addESRow(emailGrid, 'DMARC Policy',    dmarc.policy || '—');
        addESRow(emailGrid, 'DMARC Pct',       dmarc.pct != null ? dmarc.pct + '%' : '—');
        addESRow(emailGrid, 'RUA',             dmarc.rua || '—');
        addESRow(emailGrid, 'Spoofable',
          d.email_spoofable ? 'YES — ' + (d.spoofable_reason || '') : 'NO — ' + (d.spoofable_reason || ''),
          d.email_spoofable ? 'spoof-yes' : 'spoof-no'
        );

        // Subdomains
        var subList = document.getElementById('subdomain-list');
        var subs = d.subdomains || [];
        if (subList) {
          if (!subs.length) {
            subList.innerHTML = '<span class="empty">No subdomains resolved.</span>';
          } else {
            subs.forEach(function (s) {
              var item = document.createElement('div');
              item.className = 'subdomain-item';
              item.innerHTML = '<span class="sub-fqdn">' + s.fqdn + '</span>' +
                '<span class="sub-meta">' + s.type + ' → ' + (s.value || '') + ' [' + (s.source || '') + ']</span>';
              subList.appendChild(item);
            });
          }
        }
      })
      .catch(function (err) {
        var box = document.getElementById('error-box');
        var msg = document.getElementById('error-message');
        if (box) box.style.display = 'block';
        if (msg) msg.textContent = 'Failed to load "' + domain + '": ' + err.message;
      });
  });
})();
