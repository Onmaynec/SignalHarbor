/* SignalHarbor operations UI. Never interpolate unescaped server text into HTML. */
"use strict";
const $ = (id) => document.getElementById(id);
const state = {user:null, page:"overview", services:[], incidents:[], alerts:[], rules:[], users:[], teams:[], stream:null, loading:false, cursor:null, lastReplay:null, mfaDraft:null, mfaRecovery:null};
const titles = {
  overview:["REAL-TIME OVERVIEW","Обзор инфраструктуры","Состояние сервисов и реакция на инциденты"],
  incidents:["INCIDENT RESPONSE","Управление инцидентами","Подтверждение, назначение и расследование"],
  alerts:["CORRELATION ENGINE","Алерты и сигналы","Уникальные fingerprint и состояния срабатываний"],
  events:["EVENT EXPLORER","Журнал событий","События, временные окна и фильтрация"],
  services:["SERVICE CATALOG","Реестр сервисов","Сервисы и окружения в контуре наблюдения"],
  rules:["DETECTION POLICIES","Правила мониторинга","Версионированные пороги и окна"],
  inbox:["NOTIFICATION CENTER","Мои уведомления","Локальная имитация каналов доставки"],
  security:["ACCOUNT SECURITY","Безопасность","Двухфакторная аутентификация и резервные коды"],
  diagnostics:["INGEST & DETECTION","Диагностика","Задержка обработки, очередь задач и обнаружение алертов"],
  admin:["WORKSPACE SETTINGS","Управление системой","Команды, пользователи, ключи и графики"],
};
function h(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
function when(s) { return s ? new Date(s).toLocaleString("ru-RU",{dateStyle:"short",timeStyle:"short"}) : "—"; }
function tag(value) { return '<span class="tag '+h(value)+'">'+h(value)+'</span>'; }
function empty(label,detail) { return '<div class="empty"><div class="empty-icon">◇</div><strong>'+h(label)+'</strong>'+h(detail)+'</div>'; }
function panel(title,head,body) { return '<section class="panel"><div class="panel-head"><h2>'+h(title)+'</h2><span class="panel-meta">'+h(head)+'</span></div>'+body+'</section>'; }
function table(headers,rows) {
  return '<div class="table-wrap"><table><thead><tr>'+headers.map(x=>'<th>'+h(x)+'</th>').join("")+'</tr></thead><tbody>'+rows.join("")+'</tbody></table></div>';
}
function row(cells) { return '<tr>'+cells.map(x=>'<td>'+x+'</td>').join("")+'</tr>'; }
function fmt(n) { return Number(n || 0).toLocaleString("ru-RU"); }
function cookies(name) {
  const item = document.cookie.split("; ").find(x=>x.startsWith(name+"="));
  return item ? decodeURIComponent(item.slice(name.length+1)) : "";
}
async function api(path,options={}) {
  const method = options.method || "GET";
  const headers = Object.assign({"Accept":"application/json"},options.headers||{});
  if(options.body !== undefined) headers["Content-Type"] = "application/json";
  if(!["GET","HEAD"].includes(method)) headers["X-CSRF-Token"] = cookies("signalharbor_csrf");
  let response;
  try { response = await fetch(path,{method,headers,credentials:"same-origin",
    body:options.body===undefined ? undefined : JSON.stringify(options.body)}); }
  catch(_) { throw new Error("Нет соединения с сервером"); }
  const body = await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(body.message || ("HTTP "+response.status));
  return body;
}
function showMessage(text,success=false){
  $("message").textContent=text;
  $("message").className="toast"+(success?" success":"");
  setTimeout(()=>{if($("message").textContent===text)$("message").className="toast hidden";},5500);
}
function hideModal() { $("modal-layer").classList.add("hidden"); $("modal-body").replaceChildren(); }
function modal(title,formHtml,onSubmit){
  $("modal-title").textContent=title;
  $("modal-body").innerHTML='<form id="dialog-form">'+formHtml+
    '<div class="form-actions"><button type="button" id="dialog-cancel">Отмена</button><button type="submit" class="primary">Сохранить</button></div></form>';
  $("modal-layer").classList.remove("hidden");
  $("dialog-cancel").onclick=hideModal;
  $("dialog-form").onsubmit=async(ev)=>{
    ev.preventDefault();
    const submit=ev.target.querySelector('[type=submit]');submit.disabled=true;
    try{ await onSubmit(new FormData(ev.target));hideModal();showMessage("Изменения сохранены",true);await loadPage(); }
    catch(error){showMessage(error.message);submit.disabled=false;}
  };
}
function optionList(items,selected){
  return items.map(x=>'<option value="'+Number(x.id)+'"'+(x.id===selected?' selected':'')+'>'+h(x.name || x.email || x.id)+'</option>').join("");
}
function asDate(n){return n ? new Date(n).toISOString().slice(0,16) : "";}
function formField(label,name,kind="text",value="",extra=""){
  const safeName=h(name), safeValue=h(value);
  if(kind==="textarea")return '<label class="full">'+h(label)+'<textarea name="'+safeName+'" '+extra+'>'+safeValue+'</textarea></label>';
  return '<label>'+h(label)+'<input name="'+safeName+'" type="'+h(kind)+'" value="'+safeValue+'" '+extra+' required></label>';
}
function canOperate() {return ["admin","engineer","oncall","commander"].includes(state.user.role);}
function canCommand(){return ["admin","commander"].includes(state.user.role);}
function isAdmin(){return state.user.role==="admin";}
async function bootstrap(){
  try{state.user=await api("/api/v1/me");}
  catch(_){$("login").classList.remove("hidden");$("app").classList.add("hidden");return;}
  $("login").classList.add("hidden");$("app").classList.remove("hidden");
  $("user-email").textContent=state.user.email;
  $("user-role").textContent=state.user.role;
  document.querySelectorAll(".admin-only").forEach(x=>x.classList.toggle("hidden",!isAdmin()));
  document.querySelectorAll('[data-page="events"],[data-page="alerts"],[data-page="rules"]').forEach(x=>x.classList.toggle("hidden",state.user.role==="observer"));
  await loadPage();
  connectSSE();
}
async function getCatalog(){
  const jobs=[api("/api/v1/services"),isAdmin()?api("/api/v1/users"):Promise.resolve([]),api("/api/v1/teams")];
  [state.services,state.users,state.teams]=await Promise.all(jobs);
}
function connectSSE(){
  if(state.stream)state.stream.close();
  const es=new EventSource("/stream/incidents");
  state.stream=es;
  es.onopen=()=>{$("live-state").textContent="LIVE · Синхронизировано";};
  es.onerror=()=>{$("live-state").textContent="Переподключение…";};
  es.onmessage=()=>{if(!state.loading)loadPage();};
}
function head(page){
  const info=titles[page];$("breadcrumb").textContent=info[1];
  $("page-kicker").textContent=info[0];$("page-title").textContent=info[1];
  $("page-subtitle").textContent=info[2];$("page-actions").replaceChildren();
  document.querySelectorAll(".nav-link").forEach(x=>x.classList.toggle("active",x.dataset.page===page));
}
function action(label,callback,primary=false){
  const b=document.createElement("button");b.textContent=label;
  if(primary)b.className="primary";b.onclick=callback;$("page-actions").append(b);
}
async function navigate(page){
  if(["admin","diagnostics"].includes(page)&&!isAdmin())return;
  if(page!=="security"){state.mfaDraft=null;state.mfaRecovery=null;}
  state.page=page;state.cursor=null;
  await loadPage();
}
async function loadPage(){
  if(state.loading)return;
  state.loading=true;head(state.page);
  try{
    await getCatalog();
    if(state.page==="overview")await overview();
    else if(state.page==="incidents")await incidents();
    else if(state.page==="alerts")await alerts();
    else if(state.page==="events")await events();
    else if(state.page==="services")await services();
    else if(state.page==="rules")await rules();
    else if(state.page==="inbox")await inbox();
    else if(state.page==="security")await security();
    else if(state.page==="diagnostics")await diagnostics();
    else if(state.page==="admin")await admin();
  }catch(error){$("view").innerHTML=empty("Не удалось загрузить данные",error.message);showMessage(error.message);}
  state.loading=false;
}
async function overview(){
  const [stats,inc,metrics,series] = await Promise.all([
    api("/api/v1/dashboard"),api("/api/v1/incidents"),api("/api/v1/metrics"),api("/api/v1/series?hours=24")]);
  state.incidents=inc;
  $("nav-incidents").textContent=stats.activeIncidents;
  const kpis=[
    ["Сервисы",fmt(stats.serviceCount),"Под наблюдением",false],
    ["События за час",fmt(stats.eventsLastHour),"Durable ingest",false],
    ["Активные инциденты",fmt(stats.activeIncidents),"Требуют внимания",true],
    ["Ожидают ACK",fmt(stats.unackedIncidents),"Неподтверждённые",false]
  ];
  const summary='<div class="stats-grid">'+kpis.map(x=>'<div class="stat-card'+(x[3]?' highlight':'')+
    '"><div class="stat-label">'+h(x[0])+'</div><div class="stat-num">'+h(x[1])+
    '</div><div class="stat-note">'+h(x[2])+'</div></div>').join("")+'</div>';
  const rows=inc.slice(0,12).map(i=>row([
    '<button class="link-button" data-action="detail" data-id="'+i.id+'">INC-'+i.id+'</button>',
    '<span class="cell-title">'+h(i.summary)+'</span><span class="cell-muted">Service '+i.serviceId+'</span>',
    tag(i.severity),tag(i.state),when(i.createdAt)
  ]));
  const recent=panel("Последние инциденты","СОРТИРОВКА: НОВЫЕ → СТАРЫЕ",
    rows.length?table(["ID","Описание","Серьёзность","Статус","Создан"],rows):
      empty("Всё спокойно","Активных сигналов нет или данные ещё не поступали"));
  const average=(v)=>v===null?"—":(v/60).toFixed(1)+" мин";
  const metricsPanel=panel("Эффективность реагирования","ПО TIMELINE",
    '<div class="stats-grid" style="grid-template-columns:repeat(2,1fr);margin:0">'+
    '<div class="stat-card"><div class="stat-label">MTTA</div><div class="stat-num">'+average(metrics.mttaSeconds)+
    '</div><div class="stat-note">Выборка: '+metrics.ackSampleSize+'</div></div>'+
    '<div class="stat-card"><div class="stat-label">MTTR</div><div class="stat-num">'+average(metrics.mttrSeconds)+
    '</div><div class="stat-note">Выборка: '+metrics.resolutionSampleSize+'</div></div></div>');
  const maxVolume=Math.max(1,...series.points.map(x=>x.count));
  const bars=series.points.map(x=>'<div class="bar-track" title="'+h(x.at)+' · '+x.count+' событий"><div class="bar-value" style="height:'+(100*x.count/maxVolume).toFixed(2)+'%"></div></div>').join("");
  const chart=panel("Поток событий","ПОСЛЕДНИЕ 24 ЧАСА · UTC",'<div class="bar-chart">'+bars+'</div><div class="chart-foot"><span>24 часа назад</span><span>Сейчас · максимум '+fmt(maxVolume)+' / час</span></div>');
  $("view").innerHTML=summary+chart+recent+metricsPanel;
  action("Обновить",loadPage);
}
async function incidents(){
  const list=await api("/api/v1/incidents");state.incidents=list;
  const rows=list.map(i=>row([
    '<button class="link-button" data-action="detail" data-id="'+i.id+'">INC-'+i.id+'</button>',
    '<div class="cell-title">'+h(i.summary)+'</div><span class="cell-muted">Сервис #'+i.serviceId+' / среда #'+i.environmentId+'</span>',
    tag(i.severity),tag(i.state),i.ownerId?'#'+i.ownerId:'Не назначен',when(i.createdAt),
    '<button class="small" data-action="detail" data-id="'+i.id+'">Открыть</button>'
  ]));
  $("view").innerHTML=panel("Все инциденты",list.length+" ЗАПИСЕЙ",rows.length?
    table(["Инцидент","Сигнал","Severity","Состояние","Владелец","Создан",""],rows):
    empty("Инцидентов пока нет","Проверьте настройку правил и ingest"));
  action("Обновить",loadPage);
}
async function alerts(){
  const list=await api("/api/v1/alerts");state.alerts=list;
  const rows=list.map(a=>row([
    '<span class="mono">'+h(a.fingerprint.slice(0,14))+'…</span>',
    '<span class="cell-title">Rule #'+a.ruleId+'</span><span class="cell-muted">v'+a.ruleVersion+'</span>',
    '#'+a.serviceId,tag(a.state),fmt(a.count),a.value.toFixed(2),
    a.suppressed?'<span class="tag">MAINTENANCE</span>':'—',
    a.incidentId?'<button class="link-button" data-action="detail" data-id="'+a.incidentId+'">INC-'+a.incidentId+'</button>':'—'
  ]));
  $("view").innerHTML=panel("Агрегированные сигналы",list.length+" FINGERPRINT",rows.length?
    table(["Fingerprint","Правило","Сервис","Статус","Count","Value","Подавление","Инцидент"],rows):
    empty("Нет активных сигналов","События превратятся в алерты после превышения порога"));
}
async function events(cursor){
  const params = new URLSearchParams({limit:"50"});
  const svc = $("event-service")?.value||"",severity=$("event-severity")?.value||"";
  if(svc)params.set("serviceId",svc);
  if(severity)params.set("severity",severity);
  if(cursor)params.set("cursor",cursor);
  const response=await api("/api/v1/events?"+params.toString());
  state.cursor=response.nextCursor;
  const filter='<div class="toolbar"><select id="event-service"><option value="">Все сервисы</option>'+
    optionList(state.services,Number(svc))+'</select><select id="event-severity"><option value="">Любая severity</option>'+
    ["debug","info","warning","error","critical"].map(x=>'<option'+(x===severity?' selected':'')+'>'+x+'</option>').join("")+
    '</select><button data-action="filter-events">Применить фильтр</button></div>';
  const rows=response.items.map(e=>row([
    '<span class="mono">'+h(e.eventId.slice(0,22))+'</span>',
    '<span class="cell-title">'+h(e.type)+'</span>',tag(e.severity),
    '#'+e.serviceId,when(e.timestamp),e.late?'<span class="tag high">LATE</span>':'—',
    '<button class="small" data-action="payload" data-id="'+e.id+'">JSON</button>'
  ]));
  state.eventItems=response.items;
  $("view").innerHTML=filter+panel("Журнал событий",response.items.length+" РЕЗУЛЬТАТОВ",
    rows.length?table(["Event ID","Тип","Уровень","Сервис","Время","Задержка",""],rows):
    empty("Нет совпадений","Измените фильтры или отправьте тестовые события"))+
    (response.nextCursor?'<button data-action="more-events" style="margin-bottom:20px">Следующие 50 →</button>':"");
}
async function services(){
  const rows=state.services.map(s=>row([
    '<span class="cell-title">'+h(s.name)+'</span>',
    '#'+s.id,'Team '+s.teamId,
    '<button class="small" data-action="service" data-id="'+s.id+'">Здоровье / окружения</button>'
  ]));
  $("view").innerHTML=panel("Реестр",state.services.length+" СЕРВИСОВ",
    rows.length?table(["Имя","ID","Команда",""],rows):empty("Каталог пуст","Добавьте первую команду и сервис"));
  if(isAdmin())action("+ Сервис",createServiceModal,true);
}
async function rules(){
  const list=await api("/api/v1/alert-rules");state.rules=list;
  const rows=list.map(r=>row([
    '<span class="cell-title">'+h(r.name)+'</span><span class="cell-muted">v'+r.version+'</span>',
    h(r.kind),r.windowSeconds+" сек",fmt(r.threshold),r.recoverySeconds+" сек",
    tag(r.severity),r.enabled?"Активно":"Выключено"
  ]));
  $("view").innerHTML=panel("Политики обнаружения",list.length+" ПРАВИЛ",
    rows.length?table(["Имя","Тип","Окно","Порог","Recovery","Severity","Состояние"],rows):
    empty("Правила не созданы","Добавьте правило для ошибок или heartbeat"))+
    (state.lastReplay?panel("Результат replay","DRY RUN · БЕЗ УВЕДОМЛЕНИЙ",
      '<pre class="mono replay-output">'+h(JSON.stringify(state.lastReplay,null,2))+'</pre>'):"");
  if(isAdmin())action("+ Правило",createRuleModal,true);
  action("▶ Replay",replayModal);
}
async function inbox(){
  const list=await api("/api/v1/notifications");
  const rows=list.map(n=>row([
    '<button class="link-button" data-action="detail" data-id="'+n.incidentId+'">INC-'+n.incidentId+'</button>',
    tag(n.level===2?"critical":"open"),'L'+n.level,when(n.createdAt)
  ]));
  $("view").innerHTML=panel("Mock inbox",list.length+" УВЕДОМЛЕНИЙ",
    rows.length?table(["Инцидент","Приоритет","Уровень","Отправлено"],rows):
    empty("Уведомлений нет","Настройте графики дежурств и превысьте порог правила"));
}
async function security(){
  const status=await api("/api/v1/mfa/status");
  let content;
  if(status.enabled){
    content=panel("Двухфакторная аутентификация","TOTP · АКТИВНА",
      '<div class="diagnostics-note">При каждом новом входе требуется шестизначный код приложения-аутентификатора или одноразовый резервный код. '+
      'Чтобы отключить защиту, подтвердите пароль и второй фактор.</div>'+
      '<div class="form-grid">'+
      '<label>Пароль<input id="mfa-disable-password" type="password" autocomplete="current-password"></label>'+
      '<label>Код TOTP или резервный код<input id="mfa-disable-code" type="text" autocomplete="one-time-code"></label>'+
      '</div><div class="form-actions"><button data-action="mfa-disable">Отключить двухфакторную защиту</button></div>');
  }else{
    content=panel("Подключение приложения-аутентификатора","TOTP · 30 СЕКУНД",
      '<div class="diagnostics-note">Поддерживается любое TOTP-приложение. Секрет шифруется на сервере, а резервные коды выдаются только при включении. '+
      'Не делитесь секретом с другими пользователями.</div>'+
      '<div class="form-grid"><label>Подтвердите текущий пароль<input type="password" id="mfa-password" autocomplete="current-password"></label></div>'+
      '<div class="form-actions"><button class="primary" data-action="mfa-setup">Сгенерировать секрет</button></div>'+
      (state.mfaDraft?
        '<div class="diagnostics-note"><strong>Секрет для приложения:</strong> <code>'+h(state.mfaDraft.secret)+'</code>'+
        '<p>Добавьте код вручную или откройте защищённую ссылку настройки в приложении:</p>'+
        '<code style="display:block;word-break:break-all">'+h(state.mfaDraft.otpauthUri)+'</code>'+
        '<p>Настройка действительна 10 минут.</p></div>'+
        '<div class="form-grid"><label>Шестизначный код из приложения'+
        '<input type="text" id="mfa-verify-code" maxlength="6" autocomplete="one-time-code" inputmode="numeric"></label></div>'+
        '<div class="form-actions"><button class="primary" data-action="mfa-enable">Подтвердить и включить</button></div>':""));
  }
  if(state.mfaRecovery&&state.mfaRecovery.length){
    content+=panel("Резервные коды","ПОКАЗЫВАЮТСЯ ОДИН РАЗ",
      '<div class="diagnostics-note">Сохраните коды офлайн: после ухода с этой страницы они больше не будут показаны. '+
      'Каждый код действует только один раз.</div>'+
      '<pre class="mono" style="white-space:pre-wrap;word-break:break-all">'+
      h(state.mfaRecovery.join("\n"))+'</pre>'+
      '<div class="form-actions"><button data-action="mfa-copy">Скопировать коды</button></div>');
  }
  $("view").innerHTML=content;
  action("Обновить",loadPage);
}

async function diagnostics(){
  if(!isAdmin())return;
  const [data,history]=await Promise.all([api("/api/v1/ops"),api("/api/v1/history?days=30")]);
  const seconds=x=>x===null?"—":(Number(x).toFixed(1)+" с");
  const ms=x=>x===null?"—":(Number(x).toFixed(0)+" мс");
  const blocks=[
    ["Готовы к обработке",fmt(data.pendingReady),"Очередь без отложенных событий",data.pendingReady>0],
    ["Отложено до timestamp",fmt(data.pendingDeferred),"Время события ещё не наступило",false],
    ["Worker активны",fmt(data.activeWorkers),"Heartbeat за последние 20 секунд",data.activeWorkers===0],
    ["Самое старое задание",seconds(data.oldestPendingSeconds),"Возраст незавершённой задачи",false],
    ["Обработано за час",fmt(data.processedOutboxLastHour),"Из PostgreSQL, не локальный счётчик",false],
    ["Detection lag p95",ms(data.detectionLagP95Ms),"Выборка: "+data.detectionLagSamples+" новых firing",false]
  ];
  const summary='<div class="stats-grid">'+blocks.map(x=>
    '<div class="stat-card'+(x[3]?' highlight':'')+'"><div class="stat-label">'+h(x[0])+
    '</div><div class="stat-num">'+h(x[1])+'</div><div class="stat-note">'+h(x[2])+'</div></div>'
  ).join("")+'</div>';
  const rows=[
    ["Получено событий за час",fmt(data.eventsReceivedLastHour)],
    ["Поздних событий за час",fmt(data.lateEventsLastHour)],
    ["Батчей в этом API-процессе",fmt(data.processCounters.ingestBatches)],
    ["Принято этим API-процессом",fmt(data.processCounters.ingestEvents)],
    ["Отклонений 429 в этом процессе",fmt(data.processCounters.rejected429)]
  ];
  const maxHistory=Math.max(1,...history.points.map(p=>p.count));
  const historicalBars=history.points.map(p=>
    '<div class="bar-track" title="'+h(p.at)+' · '+p.count+
    ' событий"><div class="bar-value" style="height:'+
    (100*p.count/maxHistory).toFixed(2)+'%"></div></div>'
  ).join("");
  const archive=panel("Исторические события","30 ДНЕЙ · RAW + АРХИВ",
    '<div class="bar-chart">'+historicalBars+'</div>'+
    '<div class="chart-foot"><span>30 дней назад</span><span>Сегодня · максимум '+
    fmt(maxHistory)+' / день</span></div>'+
    '<div class="diagnostics-note">Хранение: raw 30 дней, агрегаты 180 дней, '+
    'завершённые инциденты 365 дней после закрытия.</div>');
  const details=panel("Метрики приёма","POSTGRESQL / PROCESS",
    table(["Показатель","Значение"],rows.map(x=>row([h(x[0]),h(x[1])]))));
  const workerRows=data.workers.map(w=>row([
    '<span class="mono">'+h(w.id.slice(0,16))+'</span>',
    w.healthy?tag("resolved"):tag("critical"),
    when(w.lastSeenAt),fmt(w.processedTotal),fmt(w.errorsTotal)
  ]));
  const workers=panel("Работа обработчиков",data.activeWorkers+" ONLINE",
    workerRows.length?table(["Worker ID","Статус","Последний heartbeat","Processed","Ошибки"],workerRows):
    empty("Нет heartbeat от worker","Убедитесь, что контейнер worker запущен и имеет доступ к PostgreSQL"));
  const note=panel("Границы измерений","SLO НЕ ПОДТВЕРЖДЁН",
    '<div class="diagnostics-note">'+h(data.note)+
    ' Метрика p95 не заменяет 30-минутный нагрузочный тест с записью оборудования, очереди, ошибок и отдельной задержки обработки.</div>');
  $("view").innerHTML=summary+archive+details+workers+note;
  action("Обновить",loadPage);
}

async function admin(){
  if(!isAdmin())return;
  const keys=await api("/api/v1/ingest-keys");
  const schedules=await api("/api/v1/schedules");
  const buttons='<div class="toolbar"><button class="primary" data-action="new-team">+ Команда</button>'+
    '<button data-action="new-user">+ Пользователь</button>'+
    '<button data-action="new-env">+ Окружение</button>'+
    '<button data-action="new-key">+ Ingest key</button>'+
    '<button data-action="new-schedule">+ On-call</button>'+
    '<button data-action="new-maintenance">+ Maintenance</button></div>';
  const rows=keys.map(k=>row(['#'+k.id,h(k.name),'#'+k.environmentId,
    k.revoked?tag("resolved"):tag("open"),
    k.revoked?'—':'<button class="small" data-action="revoke" data-id="'+k.id+'">Отозвать</button>'
  ]));
  $("view").innerHTML=buttons+
    panel("Ключи ingest","ЗНАЧЕНИЯ КЛЮЧЕЙ НЕ ОТОБРАЖАЮТСЯ",
      rows.length?table(["ID","Название","Окружение","Статус",""],rows):
        empty("Ключей нет","Создайте ключ, значение появится один раз"))+
    panel("Дежурства",schedules.length+" ГРАФИКОВ",schedules.length?
      table(["Команда","Часовой пояс","Основной","Резерв","Ротация"],
        schedules.map(s=>row(['#'+s.teamId,h(s.timezone),'#'+s.primaryId,
                             '#'+s.backupId,s.rotationMinutes+" мин"]))):
      empty("Графики не настроены","Без графика адресная доставка недоступна"));
}
async function serviceDetail(id){
  const [data,envs]=await Promise.all([
    api("/api/v1/services/"+id+"/health"),api("/api/v1/services/"+id+"/environments")]);
  const html='<div class="detail-grid">'+
    '<div class="detail"><span>Сервис</span><strong>'+h(data.service.name)+'</strong></div>'+
    '<div class="detail"><span>Инциденты</span><strong>'+data.activeIncidents+'</strong></div></div>'+
    '<h3>Окружения</h3>'+
    (envs.length?table(["ID","Среда","Последний heartbeat"],
      envs.map(e=>row(['#'+e.id,h(e.name),when(e.lastHeartbeatAt)]))):
      empty("Нет окружений","Создайте окружение в управлении"))+
    (isAdmin()?'<div class="form-actions"><button data-action="new-key">Создать ingest key</button></div>':"");
  $("modal-title").textContent="Состояние сервиса #"+id;
  $("modal-body").innerHTML=html;
  $("modal-layer").classList.remove("hidden");
}
async function incidentDetail(id){
  const [i,history]=await Promise.all([
    api("/api/v1/incidents/"+id),state.user.role==="observer"?Promise.resolve([]):api("/api/v1/incidents/"+id+"/timeline")]);
  const actions='<div class="toolbar">'+
    (canOperate()&&i.state==="open"?'<button class="primary" data-action="ack" data-id="'+i.id+'">Подтвердить ACK</button>':"")+
    (canCommand()&&i.state!=="resolved"?'<button data-action="resolve" data-id="'+i.id+'">Закрыть инцидент</button>':"")+
    (canOperate()?'<button data-action="comment" data-id="'+i.id+'">Комментарий</button>':"")+
    (canCommand()&&i.state!=="resolved"?'<button data-action="severity" data-id="'+i.id+'">Изменить severity</button>':"")+
    (canCommand()&&i.state!=="resolved"?'<button data-action="assign" data-id="'+i.id+'">Назначить</button>':"")+
    (canCommand()?'<button data-action="postmortem" data-id="'+i.id+'">Postmortem</button><a class="export-link" href="/api/v1/incidents/'+i.id+'/postmortem.md">Экспорт .md</a>':"")+'</div>';
  const details='<div class="detail-grid">'+[
    ["Состояние",tag(i.state)],["Severity",tag(i.severity)],
    ["Сервис / среда","#"+i.serviceId+" / #"+i.environmentId],
    ["Владелец",i.ownerId?"#"+i.ownerId:"Не назначен"],
    ["Создан",when(i.createdAt)],["Подтверждён",when(i.ackedAt)]
  ].map(x=>'<div class="detail"><span>'+h(x[0])+'</span><strong>'+x[1]+'</strong></div>').join("")+'</div>';
  const lines=history.map(t=>'<div class="timeline-item"><strong>'+h(t.kind)+'</strong>'+
    '<time>'+when(t.createdAt)+'</time><p>'+h(JSON.stringify(t.data,null,2))+'</p></div>').join("");
  $("modal-title").textContent="INC-"+id+" · "+i.summary;
  $("modal-body").innerHTML=actions+details+'<h3>Хронология</h3><div class="timeline">'+lines+'</div>';
  $("modal-layer").classList.remove("hidden");
}
function createServiceModal(){
  modal("Новый сервис",'<div class="form-grid">'+formField("Название","name")+
    '<label>Команда<select name="teamId" required>'+optionList(state.teams)+'</select></label></div>',
    async f=>api("/api/v1/services",{method:"POST",body:{name:f.get("name"),teamId:Number(f.get("teamId"))}}));
}
function createRuleModal(){
  modal("Новое правило",'<div class="form-grid">'+formField("Название","name")+
    '<label>Команда<select name="teamId" required>'+optionList(state.teams)+'</select></label>'+
    '<label>Тип<select name="kind"><option value="count_error">count(error)</option>'+
    '<option value="error_rate">error-rate (%)</option><option value="heartbeat_missing">heartbeat missing</option></select></label>'+
    formField("Окно (сек)","windowSeconds","number","300",'min="10"')+
    formField("Порог","threshold","number","20",'min="0" step="0.01"')+
    formField("Cooldown (сек)","cooldownSeconds","number","300",'min="0"')+
    formField("Hysteresis (сек)","recoverySeconds","number","180",'min="10"')+
    '<label>Severity<select name="severity"><option>high</option><option>critical</option><option>medium</option><option>low</option></select></label></div>',
    async f=>api("/api/v1/alert-rules",{method:"POST",body:{
      name:f.get("name"),teamId:Number(f.get("teamId")),kind:f.get("kind"),
      windowSeconds:Number(f.get("windowSeconds")),threshold:Number(f.get("threshold")),
      cooldownSeconds:Number(f.get("cooldownSeconds")),recoverySeconds:Number(f.get("recoverySeconds")),
      severity:f.get("severity"),groupLabels:[]
    }}));
}
function adminDialog(actionType){
  if(actionType==="new-team")
    return modal("Новая команда",'<div class="form-grid">'+formField("Название","name")+'</div>',
      f=>api("/api/v1/teams",{method:"POST",body:{name:f.get("name")}}));
  if(actionType==="new-user")
    return modal("Новый пользователь",'<div class="form-grid">'+
      formField("Email","email","email")+formField("Пароль (12+ символов)","password","password")+
      '<label>Роль<select name="role"><option>engineer</option><option>oncall</option><option>commander</option><option>observer</option></select></label>'+
      '<label>Команда<select name="teamId">'+optionList(state.teams)+'</select></label></div>',
      f=>api("/api/v1/users",{method:"POST",body:{email:f.get("email"),
        password:f.get("password"),role:f.get("role"),teamId:Number(f.get("teamId"))}}));
  if(actionType==="new-env")
    return modal("Новое окружение",'<div class="form-grid">'+
      '<label>Сервис<select name="serviceId">'+optionList(state.services)+'</select></label>'+
      formField("Имя окружения","name","text","production")+'</div>',
      f=>api("/api/v1/services/"+Number(f.get("serviceId"))+"/environments",{
        method:"POST",body:{name:f.get("name")}}));
  if(actionType==="new-key")
    return modal("Создать ingest key",'<p class="muted">Секрет отобразится один раз после создания.</p>'+
      '<div class="form-grid">'+formField("Название","name","text","primary")+
      formField("ID окружения","environmentId","number","1",'min="1"')+'</div>',
      async f=>{
        const result=await api("/api/v1/ingest-keys",{method:"POST",body:{
          name:f.get("name"),environmentId:Number(f.get("environmentId"))}});
        window.prompt("Сохраните ключ в надёжном месте. Он больше не будет показан:",result.key);
      });
  if(actionType==="new-schedule")
    return modal("График on-call",'<div class="form-grid">'+
      '<label>Команда<select name="teamId">'+optionList(state.teams)+'</select></label>'+
      formField("Timezone IANA","timezone","text","Europe/Tallinn")+
      '<label>Основной<select name="primaryId">'+optionList(state.users)+'</select></label>'+
      '<label>Резервный<select name="backupId">'+optionList(state.users)+'</select></label>'+
      formField("Ротация, минут","rotationMinutes","number","10080",'min="60"')+'</div>',
      f=>api("/api/v1/schedules",{method:"POST",body:{
        teamId:Number(f.get("teamId")),timezone:f.get("timezone"),
        primaryId:Number(f.get("primaryId")),backupId:Number(f.get("backupId")),
        rotationMinutes:Number(f.get("rotationMinutes"))}}));
  if(actionType==="new-maintenance")
    return modal("Maintenance window",'<div class="form-grid">'+
      formField("ID окружения","environmentId","number","1",'min="1"')+
      formField("Причина","reason","text","Planned maintenance")+
      formField("Начало (локальное)","startsAt","datetime-local",asDate(Date.now()))+
      formField("Окончание (локальное)","endsAt","datetime-local",asDate(Date.now()+3600000))+
      '</div>',f=>api("/api/v1/maintenance",{method:"POST",body:{
        environmentId:Number(f.get("environmentId")),reason:f.get("reason"),
        startsAt:new Date(f.get("startsAt")).toISOString(),endsAt:new Date(f.get("endsAt")).toISOString(),
      }}));
}
function replayModal(){
  const now=Date.now();
  const sample=JSON.stringify(Array.from({length:40},()=>({timestamp:new Date(now).toISOString(),type:"error",severity:"error"})),null,2);
  const ticks=JSON.stringify([new Date(now+6*60000).toISOString(),new Date(now+10*60000).toISOString()],null,2);
  modal("Replay без уведомлений",'<div class="form-grid"><label class="full">Правило<select name="ruleId">'+optionList(state.rules.map(r=>({id:r.id,name:r.name})))+'</select></label>'+
    formField("События (JSON array)","events","textarea",sample,"required")+
    formField("Контрольные точки времени (JSON array)","ticks","textarea",ticks,"required")+"</div>",
    async f=>{
      const response=await api("/api/v1/replay",{method:"POST",body:{ruleId:Number(f.get("ruleId")),
        events:JSON.parse(f.get("events")),ticks:JSON.parse(f.get("ticks"))}});
      state.lastReplay=response;
    });
}
async function perform(actionType,id){
  if(actionType==="mfa-setup"){
    const password=$("mfa-password")?.value||"";
    if(!password)throw new Error("Введите пароль");
    const result=await api("/api/v1/mfa/setup",{method:"POST",body:{password}});
    $("mfa-password").value="";
    state.mfaDraft=result;state.mfaRecovery=null;
    showMessage("Секрет создан. Подтвердите кодом из приложения.",true);
    return loadPage();
  }
  if(actionType==="mfa-enable"){
    const code=$("mfa-verify-code")?.value.trim()||"";
    const result=await api("/api/v1/mfa/enable",{method:"POST",body:{code}});
    state.mfaDraft=null;state.mfaRecovery=result.recoveryCodes;
    showMessage("Двухфакторная защита включена. Сохраните резервные коды.",true);
    return loadPage();
  }
  if(actionType==="mfa-copy"){
    if(state.mfaRecovery?.length){
      await navigator.clipboard.writeText(state.mfaRecovery.join("\n"));
      showMessage("Резервные коды скопированы",true);
    }
    return;
  }
  if(actionType==="mfa-disable"){
    if(!confirm("Отключить MFA и завершить все активные сеансы?"))return;
    await api("/api/v1/mfa/disable",{method:"POST",body:{
      password:$("mfa-disable-password").value,
      code:$("mfa-disable-code").value.trim()
    }});
    if(state.stream)state.stream.close();
    state.mfaDraft=null;state.mfaRecovery=null;state.user=null;
    return bootstrap();
  }
  if(actionType==="detail")return incidentDetail(id);
  if(actionType==="service")return serviceDetail(id);
  if(actionType==="payload"){
    const ev=state.eventItems.find(e=>e.id===id);
    $("modal-title").textContent="Событие #"+id;
    $("modal-body").innerHTML='<pre class="mono" style="white-space:pre-wrap;word-break:break-all">'+
      h(JSON.stringify(ev,null,2))+'</pre>';
    $("modal-layer").classList.remove("hidden");return;
  }
  if(actionType==="ack"){
    await api("/api/v1/incidents/"+id+"/ack",{method:"POST"});showMessage("Инцидент подтверждён",true);
    await incidentDetail(id);return;
  }
  if(actionType==="revoke"){
    if(!confirm("Отозвать ключ #"+id+"?"))return;
    await api("/api/v1/ingest-keys/"+id+"/revoke",{method:"POST"});showMessage("Ключ отозван",true);
    return loadPage();
  }
  if(actionType==="severity"){
    const i=await api("/api/v1/incidents/"+id);
    return modal("Severity INC-"+id,'<div class="form-grid"><label>Severity<select name="severity">'+
      ["low","medium","high","critical"].map(x=>'<option'+(i.severity===x?" selected":"")+'>'+x+"</option>").join("")+
      "</select></label></div>",
      f=>api("/api/v1/incidents/"+id+"/severity",{method:"POST",body:{severity:f.get("severity"),expectedVersion:i.version}}));
  }
  if(actionType==="assign"){
    const i=await api("/api/v1/incidents/"+id);
    const options=state.users.filter(x=>x.teamId===i.teamId);
    return modal("Владелец INC-"+id,'<label>Ответственный<select name="ownerId">'+optionList(options)+"</select></label>",
      f=>api("/api/v1/incidents/"+id+"/assign",{method:"POST",body:{ownerId:Number(f.get("ownerId")),expectedVersion:i.version}}));
  }
  if(actionType==="resolve")
    return modal("Закрыть инцидент #"+id,formField("Причина закрытия","reason","textarea","",'minlength="5" required'),
      async f=>{await api("/api/v1/incidents/"+id+"/resolve",{method:"POST",
        body:{reason:f.get("reason")}});});
  if(actionType==="comment")
    return modal("Комментарий к INC-"+id,formField("Текст","text","textarea","","required"),
      f=>api("/api/v1/incidents/"+id+"/comments",{method:"POST",body:{text:f.get("text")}}));
  if(actionType==="postmortem")
    return modal("Postmortem INC-"+id,'<div class="form-grid">'+
      formField("Влияние","impact","textarea","","required minlength=5")+
      formField("Корневая причина","rootCause","textarea","","required minlength=5")+
      formField("План действий (JSON-массив)","actionItems","textarea","[]","required")+'</div>',
      f=>api("/api/v1/incidents/"+id+"/postmortem",{method:"PUT",body:{
        impact:f.get("impact"),rootCause:f.get("rootCause"),
        actionItems:JSON.parse(f.get("actionItems"))}}));
  if(actionType==="filter-events")return events();
  if(actionType==="more-events")return events(state.cursor);
  if(actionType.startsWith("new-"))return adminDialog(actionType);
}
$("login-form").onsubmit=async(e)=>{
  e.preventDefault();$("login-error").textContent="";
  try{await api("/api/v1/login",{method:"POST",body:{
    email:$("login-email").value,password:$("login-password").value,
    mfaCode:$("login-mfa").value||null}});$("login-password").value="";$("login-mfa").value="";await bootstrap();}
  catch(error){$("login-error").textContent=error.message;}
};
$("logout").onclick=async()=>{
  try{await api("/api/v1/logout",{method:"POST"});}catch(_){}
  if(state.stream)state.stream.close();state.user=null;state.mfaDraft=null;state.mfaRecovery=null;await bootstrap();
};
$("nav").onclick=e=>{
  const btn=e.target.closest(".nav-link");if(btn)navigate(btn.dataset.page);
};
$("view").onclick=async e=>{
  const btn=e.target.closest("[data-action]");if(!btn)return;
  try{await perform(btn.dataset.action,Number(btn.dataset.id));}
  catch(error){showMessage(error.message);}
};
$("modal-body").onclick=async e=>{
  const btn=e.target.closest("[data-action]");if(!btn)return;
  try{await perform(btn.dataset.action,Number(btn.dataset.id));}
  catch(error){showMessage(error.message);}
};
$("modal-close").onclick=hideModal;
$("modal-layer").onclick=e=>{if(e.target.id==="modal-layer")hideModal();};
document.addEventListener("keydown",e=>{if(e.key==="Escape")hideModal();});
bootstrap();
