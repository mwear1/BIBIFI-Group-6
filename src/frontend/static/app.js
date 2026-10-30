(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const notice = document.querySelector('[data-notice]');
  let historyPage = 1;
  const showNotice = (message, isError = false) => {
    if (!notice) return;
    notice.textContent = message;
    notice.classList.toggle('error', isError);
    notice.hidden = false;
    clearTimeout(showNotice.timer);
    showNotice.timer = setTimeout(() => { notice.hidden = true; }, 4500);
  };
  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
    if (['POST','PUT','PATCH','DELETE'].includes((options.method || 'GET').toUpperCase())) headers.set('X-CSRF-Token', csrf);
    const response = await fetch(path, { credentials: 'same-origin', ...options, headers });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) { location.assign('/login'); throw new Error('Your session expired. Please sign in again.'); }
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
  }
  const escText = (value) => value == null || value === '' ? '—' : String(value);
  const cell = (value) => { const td = document.createElement('td'); td.textContent = escText(value); return td; };
  function fillSelect(select, items, key, label, firstText) {
    select.replaceChildren(new Option(firstText, ''));
    items.forEach(item => select.add(new Option(label(item), item[key])));
  }
  function eventRow(event) {
    const tr = document.createElement('tr');
    [event.person?.name, event.event_type?.replaceAll('_',' '), event.room?.name, event.timestamp ? new Date(event.timestamp).toLocaleString() : '', event.recorded_by].forEach(value => tr.append(cell(value)));
    return tr;
  }
  async function loadDashboard() {
    const gallery = await api('/api/occupancy/gallery');
    const roomsData = await api('/api/occupancy/rooms');
    const eventsData = await api('/api/events?limit=8');
    document.querySelector('[data-gallery-count]').textContent = gallery.count;
    document.querySelector('[data-room-count]').textContent = roomsData.rooms.length;
    document.querySelector('[data-event-count]').textContent = eventsData.events.length;
    const roomGrid = document.querySelector('[data-room-grid]'); roomGrid.replaceChildren();
    if (!roomsData.rooms.length) roomGrid.append(Object.assign(document.createElement('p'), { className: 'muted', textContent: 'No active rooms yet.' }));
    roomsData.rooms.forEach(item => {
      const card = document.createElement('article'); card.className = 'room-card';
      const title = document.createElement('strong'); title.textContent = item.room.name;
      const count = document.createElement('span'); count.textContent = `${item.count}${item.room.capacity ? ` / ${item.room.capacity}` : ''} people`;
      card.append(title, count); roomGrid.append(card);
    });
    const tbody = document.querySelector('[data-recent-events]'); tbody.replaceChildren();
    if (!eventsData.events.length) tbody.append(emptyRow(5, 'No movement events recorded yet.'));
    eventsData.events.forEach(event => tbody.append(eventRow(event)));
  }
  function emptyRow(span, message) { const tr = document.createElement('tr'); const td = cell(message); td.colSpan = span; td.className = 'muted'; tr.append(td); return tr; }
  async function loadEventPage() {
    const [persons, rooms] = await Promise.all([api('/api/persons'), api('/api/rooms')]);
    document.querySelectorAll('[data-person-options]').forEach(select => fillSelect(select, persons.persons, 'person_id', p => `${p.name} · ${p.identifier}`, select.options[0].text));
    document.querySelectorAll('[data-room-options]').forEach(select => fillSelect(select, rooms.rooms, 'room_id', r => r.name, select.options[0].text));
    const form = document.querySelector('[data-event-form]');
    const eventType = form.elements.event_type; const roomField = document.querySelector('[data-room-field]');
    const syncRoom = () => { roomField.hidden = !eventType.value.startsWith('ROOM_'); form.elements.room_id.required = !roomField.hidden; };
    eventType.addEventListener('change', syncRoom); syncRoom();
    form.addEventListener('submit', async e => {
      e.preventDefault(); const payload = { person_id: Number(form.elements.person_id.value) };
      let path = '/api/events/gallery/entry';
      if (eventType.value === 'GALLERY_EXIT') path = '/api/events/gallery/exit';
      if (eventType.value.startsWith('ROOM_')) path = `/api/events/rooms/${Number(form.elements.room_id.value)}/${eventType.value === 'ROOM_ENTER' ? 'entry' : 'exit'}`;
      try { await api(path, { method: 'POST', body: JSON.stringify(payload) }); showNotice('Movement recorded.'); form.reset(); syncRoom(); await loadHistory(); }
      catch (error) { showNotice(error.message, true); }
    });
    document.querySelector('[data-history-form]').addEventListener('submit', e => { e.preventDefault(); historyPage = 1; loadHistory().catch(error => showNotice(error.message, true)); });
    document.querySelector('[data-history-prev]').addEventListener('click', () => { if (historyPage > 1) { historyPage--; loadHistory().catch(error => showNotice(error.message, true)); } });
    document.querySelector('[data-history-next]').addEventListener('click', () => { historyPage++; loadHistory().catch(error => showNotice(error.message, true)); });
    await loadHistory();
  }
  async function loadHistory() {
    const form = document.querySelector('[data-history-form]');
    const query = new URLSearchParams({limit:'100', page:String(historyPage)});
    ['person_id','room_id','event_type','date_from','date_to'].forEach(name => { if (form.elements[name].value) query.set(name, form.elements[name].value); });
    const data = await api('/api/events?' + query);
    const tbody = document.querySelector('[data-event-history]'); tbody.replaceChildren();
    if (!data.events.length) tbody.append(emptyRow(5, 'No matching events.'));
    data.events.forEach(event => tbody.append(eventRow(event)));
    document.querySelector('[data-history-page]').textContent = 'Page ' + data.page;
    document.querySelector('[data-history-prev]').disabled = data.page <= 1;
    document.querySelector('[data-history-next]').disabled = !data.has_more;
  }
  async function loadAdmin() {
    await Promise.all([loadUsers(), loadAdminPersons(), loadAdminRooms(), loadAudit()]);
    document.querySelectorAll('[data-admin-form]').forEach(form => form.addEventListener('submit', async e => {
      e.preventDefault(); const values = Object.fromEntries(new FormData(form)); const kind = form.dataset.adminForm;
      if (kind === 'room') { values.capacity = values.capacity ? Number(values.capacity) : null; values.description ||= null; }
      if (kind === 'person') values.identifier = values.identifier.trim();
      try { await api(`/api/admin/${kind === 'user' ? 'users' : kind === 'person' ? 'persons' : 'rooms'}`, {method:'POST', body:JSON.stringify(values)}); form.reset(); showNotice('Saved successfully.'); if (kind === 'user') await loadUsers(); if (kind === 'person') await loadAdminPersons(); if (kind === 'room') await loadAdminRooms(); }
      catch (error) { showNotice(error.message, true); }
    }));
  }
  async function loadUsers() {
    const data = await api('/api/admin/users');
    const tbody = document.querySelector('[data-users]'); tbody.replaceChildren();
    data.users.forEach(user => {
      const tr = document.createElement('tr');
      tr.append(cell(user.username + (user.full_name ? ' \u00b7 ' + user.full_name : '')), cell(user.role), cell(user.is_active ? 'Active' : 'Disabled'));
      const td = document.createElement('td');
      const role = document.createElement('select');
      ['Guest','Employee','Administrator'].forEach(name => role.add(new Option(name,name)));
      role.value = user.role; role.setAttribute('aria-label', 'Role for ' + user.username);
      role.addEventListener('change', async () => {
        try { await api('/api/admin/users/' + user.user_id + '/role', {method:'PUT',body:JSON.stringify({role:role.value})}); showNotice('Role updated.'); }
        catch(error) { role.value=user.role; showNotice(error.message,true); }
      });
      const edit = document.createElement('button');
      edit.type='button'; edit.className='button button-quiet'; edit.textContent='Edit';
      edit.addEventListener('click', async () => {
        const username = prompt('Username', user.username); if (username === null) return;
        const fullName = prompt('Full name (blank clears it)', user.full_name || ''); if (fullName === null) return;
        const email = prompt('Email (blank clears it)', user.email || ''); if (email === null) return;
        try {
          await api('/api/admin/users/' + user.user_id, {method:'PUT',body:JSON.stringify({username:username.trim(),full_name:fullName || null,email:email || null})});
          showNotice('Account updated.'); await loadUsers();
        } catch(error) { showNotice(error.message,true); }
      });
      const status = document.createElement('button');
      status.type='button'; status.className='button button-quiet'; status.textContent=user.is_active ? 'Disable' : 'Enable';
      status.addEventListener('click', async () => {
        try { await api('/api/admin/users/' + user.user_id + (user.is_active ? '/disable' : '/enable'), {method:'POST'}); showNotice(user.is_active ? 'Account disabled.' : 'Account enabled.'); await loadUsers(); }
        catch(error) { showNotice(error.message,true); }
      });
      td.append(role,edit,status); tr.append(td); tbody.append(tr);
    });
    if (!data.users.length) tbody.append(emptyRow(4,'No accounts found.'));
  }

  async function loadAdminPersons() {
    const data = await api('/api/admin/persons');
    const tbody = document.querySelector('[data-admin-persons]'); tbody.replaceChildren();
    data.persons.forEach(person => {
      const tr = document.createElement('tr');
      tr.append(cell(person.name),cell(person.identifier),cell(person.is_active ? 'Active' : 'Disabled'));
      const td = document.createElement('td');
      const edit = document.createElement('button');
      edit.type='button'; edit.className='button button-quiet'; edit.textContent='Edit';
      edit.addEventListener('click', async () => {
        const name = prompt('Person name',person.name); if (name === null) return;
        const identifier = prompt('Person identifier',person.identifier); if (identifier === null) return;
        try { await api('/api/admin/persons/' + person.person_id,{method:'PUT',body:JSON.stringify({name:name.trim(),identifier:identifier.trim()})}); showNotice('Tracked person updated.'); await loadAdminPersons(); }
        catch(error) { showNotice(error.message,true); }
      });
      const status = document.createElement('button');
      status.type='button'; status.className='button button-quiet'; status.textContent=person.is_active ? 'Disable' : 'Enable';
      status.addEventListener('click',async()=>{try{await api('/api/admin/persons/' + person.person_id + (person.is_active ? '/disable' : '/enable'),{method:'POST'});showNotice(person.is_active?'Tracked person disabled.':'Tracked person enabled.');await loadAdminPersons();}catch(error){showNotice(error.message,true);}});
      td.append(edit,status);tr.append(td);tbody.append(tr);
    });
    if (!data.persons.length) tbody.append(emptyRow(4,'No tracked people found.'));
  }

  async function loadAdminRooms() {
    const data = await api('/api/admin/rooms');
    const tbody = document.querySelector('[data-admin-rooms]'); tbody.replaceChildren();
    data.rooms.forEach(room => {
      const tr = document.createElement('tr');
      tr.append(cell(room.name),cell(room.capacity == null ? 'No limit' : room.capacity),cell(room.is_active ? 'Active' : 'Disabled'));
      const td = document.createElement('td');
      const edit = document.createElement('button');
      edit.type='button'; edit.className='button button-quiet'; edit.textContent='Edit';
      edit.addEventListener('click',async()=>{
        const name=prompt('Room name',room.name);if(name===null)return;
        const description=prompt('Description (blank clears it)',room.description||'');if(description===null)return;
        const capacity=prompt('Capacity (blank means no limit)',room.capacity==null?'':String(room.capacity));if(capacity===null)return;
        const parsed=capacity.trim()===''?null:Number(capacity);
        if(parsed!==null&&(!Number.isInteger(parsed)||parsed<1)){showNotice('Capacity must be a positive whole number or blank.',true);return;}
        try{await api('/api/admin/rooms/'+room.room_id,{method:'PUT',body:JSON.stringify({name:name.trim(),description:description||null,capacity:parsed})});showNotice('Room updated.');await loadAdminRooms();}
        catch(error){showNotice(error.message,true);}
      });
      const status=document.createElement('button');
      status.type='button';status.className='button button-quiet';status.textContent=room.is_active?'Disable':'Enable';
      status.addEventListener('click',async()=>{try{await api('/api/admin/rooms/'+room.room_id+(room.is_active?'/disable':'/enable'),{method:'POST'});showNotice(room.is_active?'Room disabled.':'Room enabled.');await loadAdminRooms();}catch(error){showNotice(error.message,true);}});
      td.append(edit,status);tr.append(td);tbody.append(tr);
    });
    if (!data.rooms.length) tbody.append(emptyRow(4,'No rooms found.'));
  }
  async function loadAudit() {
    const data = await api('/api/admin/audit-logs?limit=50'); const tbody=document.querySelector('[data-audit]'); tbody.replaceChildren();
    data.audit_logs.forEach(item => { const tr=document.createElement('tr'); [item.timestamp ? new Date(item.timestamp).toLocaleString() : '', item.username, item.action, item.result].forEach(value=>tr.append(cell(value))); tbody.append(tr); });
    if (!data.audit_logs.length) tbody.append(emptyRow(4,'No audit activity yet.'));
  }
  const loginForm = document.querySelector('[data-login-form]');
  if (loginForm) loginForm.addEventListener('submit', async e => { e.preventDefault(); const values=Object.fromEntries(new FormData(loginForm)); try { await api('/api/auth/login',{method:'POST',body:JSON.stringify(values)}); location.assign('/dashboard'); } catch(error) { showNotice(error.message,true); } });
  const logout = document.querySelector('[data-logout]');
  if (logout) logout.addEventListener('click', async () => { try { await api('/api/auth/logout',{method:'POST'}); location.assign('/login'); } catch(error) { showNotice(error.message,true); } });
  if (document.querySelector('[data-stats]')) loadDashboard().catch(error=>showNotice(error.message,true));
  if (document.querySelector('[data-event-form]')) loadEventPage().catch(error=>showNotice(error.message,true));
  if (document.querySelector('[data-admin-form]')) loadAdmin().catch(error=>showNotice(error.message,true));
})();
