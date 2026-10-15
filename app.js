(() => {
  const root = document.documentElement;
  const saved = (() => { try { return localStorage.getItem('rix-theme'); } catch (_) { return null; } })();
  if (saved === 'light' || saved === 'dark') root.dataset.theme = saved;
  document.querySelectorAll('[data-theme-toggle]').forEach(button => button.addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem('rix-theme', root.dataset.theme); } catch (_) {}
  }));
  const protocolHints = {vless:'UUID؛ TLS یا Reality', vmess:'UUID؛ TLS یا بدون TLS', trojan:'رمز عبور؛ TLS', shadowsocks:'رمز مستقل؛ TCP'};
  document.querySelectorAll('[data-client-form]').forEach(form => {
    const protocol = form.querySelector('[data-protocol-select]');
    const transport = form.querySelector('[data-transport-select]');
    const security = form.querySelector('[data-security-select]');
    const hint = form.querySelector('[data-protocol-hint]');
    const sync = () => {
      const p = protocol?.value || 'vless';
      if (hint) hint.textContent = protocolHints[p] || '';
      form.querySelectorAll('[data-show-protocol]').forEach(el => {
        el.classList.toggle('show-field', (el.dataset.showProtocol || '').split(',').includes(p));
      });
      form.querySelectorAll('[data-show-transport]').forEach(el => {
        el.classList.toggle('show-field', (el.dataset.showTransport || '').split(',').includes(transport?.value || 'tcp'));
      });
      if (p === 'shadowsocks') { transport.value = 'tcp'; security.value = 'none'; transport.disabled = true; security.disabled = true; }
      else if (p === 'trojan') { security.value = 'tls'; security.disabled = true; transport.disabled = false; }
      else { transport.disabled = false; security.disabled = false; }
      if (p !== 'vless' && security.value === 'reality') security.value = 'tls';
      if (p !== 'vless') form.querySelector('[name="flow"]')?.closest('.field')?.classList.remove('show-field');
      form.querySelectorAll('[data-show-transport]').forEach(el => el.classList.toggle('show-field', (el.dataset.showTransport || '').split(',').includes(transport?.value || 'tcp')));
    };
    [protocol, transport, security].filter(Boolean).forEach(el => el.addEventListener('change', sync));
    sync();
    form.addEventListener('submit', () => { if (transport.disabled) transport.disabled = false; if (security.disabled) security.disabled = false; });
  });
  document.querySelectorAll('[data-table-filter]').forEach(input => {
    const table = document.getElementById(input.dataset.tableFilter);
    input.addEventListener('input', () => {
      const query = input.value.toLowerCase().trim();
      table?.querySelectorAll('tbody tr').forEach(row => { row.hidden = query && !row.innerText.toLowerCase().includes(query); });
    });
  });
  const copy = async text => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      const temp = document.createElement('textarea'); temp.value = text; temp.style.position = 'fixed'; temp.style.opacity = '0';
      document.body.appendChild(temp); temp.select(); document.execCommand('copy'); temp.remove();
    }
  };
  document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
    await copy(button.dataset.copy || ''); const old = button.textContent; button.textContent = 'کپی شد ✓'; setTimeout(() => button.textContent = old, 1400);
  }));
  document.querySelectorAll('[data-copy-target]').forEach(button => button.addEventListener('click', async () => {
    const target = document.getElementById(button.dataset.copyTarget); if (target) await copy(target.value);
    const old = button.textContent; button.textContent = 'کپی شد ✓'; setTimeout(() => button.textContent = old, 1400);
  }));
  document.querySelectorAll('form[data-confirm]').forEach(form => form.addEventListener('submit', event => {
    if (!window.confirm(form.dataset.confirm || 'ادامه می‌دهی؟')) event.preventDefault();
  }));
})();
