from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, delete, func, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import Session, select

from app.activity import tracked, worker_state
from app.deps import SessionDep, require_admin
from app.fail2ban import GuardView, _remember, guard_snapshot, guard_totals, read_bans, sync_node_guard, unban
from app.firewall import sync_node_firewall
from app.mihomo import days_left, is_expired, node_clash_sub_base, render_profile
from app.models import AppSetting, Client, ClientPingReport, ClientPlacement, ConfigDoc, InboundTemplate, Node, NodeInbound, NodeTemplateAssignment
from app.node_updates import check_updates, start_update
from app.overview import aggregate_client_usage, probe_nodes, probe_nodes_presence, remember_last_online, store_probe
from app.reachability import inbound_ports, probe_nodes_rf, store as store_rf_view
from app.sub_link import client_sub_url
from app.ssh_access import ConfirmHostKey, HostIdentityError, verify_install_host
from app.provision import (
    apply_sub_settings,
    client_access_lock,
    delete_client_remote,
    node_template_ids,
    fleet_template_ids,
    fleet_inbound_counts,
    provision_client,
    apply_node_templates,
    provision_templates,
    reconcile_all_nodes,
    reconcile_node_templates,
    push_server_names,
    reconcile_clients,
    set_node_template_ids,
    split_csv,
    sync_node,
    sync_template_fields,
    templates_for_node,
)
from app.routers.updates import delete_installer
from app.tls_sni import fetch_dest_sni, parse_dest
from app.util import expire_from_days, format_bytes, new_token, new_uuid, slugify
from app.flags import normalize_flags, to_iso
from app.xui import XuiClient, XuiError, normalize_panel_url, public_host_from_url, require_panel_transport
from app.xui_install import credential_key, prepare_install, start_install

router = APIRouter(prefix='/api', dependencies=[Depends(require_admin)])

# Как долго лампочке «доступен из РФ» не нужна свежая проба (минуты).
# Планировщик перепроверяет каждые 10 минут, поэтому 15 — с запасом.
RF_TTL_MINUTES = 15


class InstallTrust(BaseModel):
    ssh_fingerprint: str = ''


class NodeIn(InstallTrust):
    flag: str = ''
    name: str
    clash_name: str = ''
    panel_url: str = ''
    api_token: str = ''
    install: bool = False
    install_kind: str = 'xui'
    host: str = ''
    ssh_user: str = 'root'
    ssh_port: int = 22
    ssh_password: str = ''


class NodePatch(BaseModel):
    flag: str | None = None
    name: str | None = None
    clash_name: str | None = None
    panel_url: str | None = None
    api_token: str | None = None
    public_host: str | None = None
    enabled: bool | None = None
    sort_order: int | None = None
    sub_port: int | None = None
    sub_path: str | None = None
    sub_clash_path: str | None = None
    sub_scheme: str | None = None
    ssh_user: str | None = None
    ssh_port: int | None = None
    ssh_password: str | None = None
    template_ids: list[int] | None = None


class InboundPatch(BaseModel):
    server_names: str | None = None
    display_prefix: str | None = None
    use_in_sub: bool | None = None
    extra_snis: str | None = None
    use_global_sni: bool | None = None
    snis_locked: bool | None = None
    provider_label: str | None = None
    push_panel: bool = True


class TemplateIn(BaseModel):
    name: str
    port: int
    protocol: str = 'vless'
    listen: str = ''
    network: str = 'grpc'
    security: str = 'reality'
    dest: str = 'www.cloudflare.com:443'
    server_names: str = 'www.cloudflare.com'
    grpc_service_name: str = 'grpc'
    grpc_authority: str = ''
    grpc_multi_mode: bool = False
    xhttp_path: str = '/'
    xhttp_host: str = ''
    xhttp_mode: str = 'auto'
    ws_path: str = '/'
    ws_host: str = ''
    fingerprint: str = 'chrome'
    flow: str = ''
    spider_x: str = '/'
    short_ids: str = ''
    sniffing: bool = False
    tls_cert_file: str = ''
    tls_key_file: str = ''
    tls_alpn: str = 'h2,http/1.1'
    tls_server_name: str = ''
    reject_unknown_sni: bool = False
    extra_snis: str = ''
    use_global_sni: bool = False
    enabled: bool = True
    use_in_sub: bool = True
    provider_label: str = ''
    flags: str = ''


class ClientIn(BaseModel):
    name: str
    days: int = 30
    traffic_gb: int = 0
    limit_ip: int = 0
    note: str = ''
    cabinet_account_id: str | None = None

    @field_validator('cabinet_account_id')
    @classmethod
    def clean_cabinet_account_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        if len(value) > 64 or not value.replace('-', '').replace('_', '').isalnum():
            raise ValueError('cabinet_account_id: буквы, цифры, дефис и подчёркивание, до 64 символов')
        return value


class ClientPatch(BaseModel):
    name: str | None = None
    enable: bool | None = None
    days: int | None = None
    add_days: int | None = None
    traffic_gb: int | None = None
    limit_ip: int | None = None
    note: str | None = None


class ConfigIn(BaseModel):
    yaml_text: str
    pool_group_names: str | None = None
    global_extra_snis: str | None = None


def _node_out(node: Node, session: Session | None = None, *, include_install: bool = False, assignments: dict | None = None) -> dict:
    out = {
        'id': node.id,
        'flag': node.flag,
        'name': node.name,
        'clash_name': node.clash_name,
        'clash_prefix': node.clash_prefix(),
        'panel_url': node.panel_url,
        'has_api_token': bool((node.api_token or '').strip()),
        'public_host': node.public_host,
        'enabled': node.enabled,
        'sort_order': node.sort_order,
        'last_sync_at': node.last_sync_at.isoformat() if node.last_sync_at else None,
        'last_error': node.last_error,
        'sub_port': node.sub_port,
        'sub_path': node.sub_path,
        'sub_clash_path': node.sub_clash_path,
        'sub_scheme': node.sub_scheme,
        'ssh_user': node.ssh_user or 'root',
        'ssh_port': node.ssh_port or 22,
        'has_ssh_password': bool((node.ssh_password or '').strip()),
        'ssh_auth': (node.ssh_auth or '') or ('password' if (node.ssh_password or '').strip() else 'none'),
        'firewall_on': bool(node.firewall_on),
        'firewall_note': node.firewall_note or '',
        'rf_ok': bool(node.rf_ok),
        'rf_note': node.rf_note or '',
        'rf_checked_at': _as_utc(node.rf_checked_at).isoformat() if node.rf_checked_at else None,
        'xui_version': node.xui_version or '',
        'xray_version': node.xray_version or '',
        'version_checked_at': _as_utc(node.version_checked_at).isoformat() if node.version_checked_at else None,
        'panel_check_error': node.panel_check_error,
        'xray_check_error': node.xray_check_error,
        'panel_latest_version': node.panel_latest_version or '',
        'xray_latest_version': node.xray_latest_version or '',
        'update_checked_at': _as_utc(node.update_checked_at).isoformat() if node.update_checked_at else None,
        'update_state': node.update_state or '',
        'update_kind': node.update_kind or '',
        'update_target_version': node.update_target_version or '',
        'install_state': node.install_state or '',
        'install_kind': node.install_kind or '',
        'install_step': node.install_step(),
        'exporter_state': node.exporter_state or '',
        'exporter_note': node.exporter_note or '',
        'clash_sub_base': node_clash_sub_base(node),
    }
    if include_install:
        out['install_log'] = node.install_log or ''
    if assignments is not None:
        out['template_ids'] = assignments.get(node.id, [])
    elif session is not None and node.id is not None:
        out['template_ids'] = node_template_ids(session, node.id)
    return out


@router.get('/nodes')
def list_nodes(session: SessionDep) -> list[dict]:
    rows = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    assignments = fleet_template_ids(session)
    return [_node_out(n, assignments=assignments) for n in rows]


@router.post('/nodes/{node_id}/update')
@tracked('Запуск обновления компонента')
def node_update(node_id: int, kind: str, session: SessionDep) -> dict:
    """Обновить панель/ядро ноды через API панели. kind: 'panel' | 'xray'.

    Мастер дёрнул API панели и вернул 'running'; фактический успех разрешает
    reconcile_update по мере снятия версий обзором/планировщиком (откат не нужен).
    """
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    return start_update(session, node, kind)


@router.get('/nodes/{node_id}')
def get_node(node_id: int, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    return _node_out(node, session, include_install=True)


@router.post('/nodes/{node_id}/panel-token')
def reveal_panel_token(node_id: int, session: SessionDep):
    node = session.get(Node, node_id)
    if node is None or not node.api_token:
        raise HTTPException(404, 'Токен панели отсутствует')
    return JSONResponse({'token': node.api_token}, headers={'Cache-Control': 'no-store'})


@router.post('/nodes/{node_id}/install-credentials')
def take_install_credentials(node_id: int, session: SessionDep):
    import json

    value = session.execute(delete(AppSetting).where(AppSetting.key == credential_key(node_id))
                            .returning(AppSetting.value)).scalar_one_or_none()
    if value is None:
        raise HTTPException(404, 'Реквизиты уже получены или отсутствуют')
    payload = json.loads(value)
    session.commit()
    return JSONResponse(payload, headers={'Cache-Control': 'no-store'})


@router.post('/nodes/{node_id}/install-log/clear')
@tracked('Очистка журнала установки')
def clear_install_log(node_id: int, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    if (node.install_state or '') == 'installing':
        raise HTTPException(400, 'Установка ещё идёт')
    node.install_log = ''
    if node.install_state in {'done', 'failed'}:
        node.install_state = ''
    session.add(node)
    session.commit()
    session.refresh(node)
    return _node_out(node, session, include_install=True)


@router.post('/nodes/{node_id}/exporter')
@tracked('Запуск агента метрик')
def install_node_exporter(node_id: int, session: SessionDep) -> dict:
    from app.exporters import start_exporters

    if session.get(Node, node_id) is None:
        raise HTTPException(404, 'Сервер не найден')
    try:
        start_exporters(session, node_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {'ok': True, 'state': 'installing'}


@router.post('/exporters')
@tracked('Запуск агентов флота')
def install_exporters(session: SessionDep) -> dict:
    from app.exporters import start_exporters

    try:
        count = start_exporters(session)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {
        'ok': True,
        'logs': [f'Ставлю экспортёры на {count} серверах. Ход установки виден в колонке «Агент».'],
    }


def _host_identity_response(exc):
    if isinstance(exc, ConfirmHostKey):
        return HTTPException(409, {'code': 'confirm_ssh_host_key', 'address': exc.address,
                                   'algorithm': exc.algorithm, 'fingerprint': exc.fingerprint})
    return HTTPException(400, str(exc))


def _start_node_install(node):
    if node.is_grafana():
        from app.grafana_host import start_grafana_install

        start_grafana_install(node.id)
    else:
        start_install(node.id)


@router.post('/nodes/{node_id}/retry-install')
@tracked('Повтор установки после проверки SSH')
def retry_install(node_id: int, body: InstallTrust, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'Сервер не найден')
    if not node.needs_install_host_key():
        raise HTTPException(409, 'Повтор доступен для установки, остановленной при проверке ключа SSH')
    try:
        verify_install_host(node.public_host, node.ssh_port or 22, body.ssh_fingerprint)
    except HostIdentityError as exc:
        raise _host_identity_response(exc) from exc
    queued = session.execute(update(Node).where(
        Node.id == node_id, Node.install_state == node.install_state, Node.public_host == node.public_host,
        Node.ssh_port == node.ssh_port, Node.install_kind == node.install_kind,
        Node.enabled.is_(False), Node.panel_url == '', Node.api_token == '',
    ).values(install_state='installing', install_log='Повтор установки после проверки SSH', last_error=''))
    if queued.rowcount != 1:
        raise HTTPException(409, 'Состояние сервера изменилось. Обновите карточку.')
    worker_state(session, node, 'install', 'Установка ' + node.install_kind, 'running', 'Сервер добавлен в очередь')
    session.commit()
    _start_node_install(node)
    return {'ok': True}


@router.post('/nodes')
@tracked('Добавление сервера')
def create_node(body: NodeIn, session: SessionDep) -> dict:
    if body.install:
        try:
            from app.xui_install import install_product

            kind = install_product(body.install_kind)
            node = prepare_install(
                session,
                flag=body.flag,
                name=body.name,
                clash_name=body.clash_name,
                host=body.host,
                ssh_user=body.ssh_user,
                ssh_password=body.ssh_password,
                ssh_port=body.ssh_port,
                kind=kind,
                ssh_fingerprint=body.ssh_fingerprint,
            )
        except HostIdentityError as exc:
            raise _host_identity_response(exc) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        _start_node_install(node)
        if kind == 'grafana':
            note = 'Сервер в списке. Grafana ставится, журнал — на карточке сервера.'
        else:
            note = 'Сервер в списке. 3x-ui ставится, журнал — на карточке сервера.'
        return {
            'node': _node_out(node, session),
            'logs': [note],
        }
    token = body.api_token.strip()
    if not token:
        raise HTTPException(400, 'Нужен API Token')
    panel_url = normalize_panel_url(body.panel_url)
    if not panel_url:
        raise HTTPException(400, 'Нужен адрес панели')
    try:
        require_panel_transport(panel_url)
    except XuiError as exc:
        raise HTTPException(400, str(exc)) from exc
    node = Node(
        flag=to_iso(body.flag) or body.flag.strip(),
        name=body.name.strip(),
        clash_name=(body.clash_name or body.name).strip(),
        panel_url=panel_url,
        api_token=token,
        public_host=public_host_from_url(panel_url),
        enabled=True,
    )
    session.add(node)
    session.commit()
    session.refresh(node)
    logs: list[str] = []
    try:
        with XuiClient(node) as xui:
            xui.login()
        logs.append('API ok')
        sync_node(session, node)
        logs.append('порты подтянуты')
        check_updates(node)
        session.commit()
    except XuiError as exc:
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        logs.append(str(exc))
    return {'node': _node_out(node, session), 'logs': logs}


@router.post('/nodes/{node_id}/test')
@tracked('Проверка API панели')
def test_node(node_id: int, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    try:
        with XuiClient(node) as xui:
            errors = []
            status = {}
            try:
                status = xui.server_status()
            except XuiError as exc:
                errors.append(str(exc))
            try:
                apply_sub_settings(node, xui.panel_settings())
            except XuiError as exc:
                errors.append(str(exc))
            if len(errors) == 2:
                raise XuiError('; '.join(dict.fromkeys(errors)))
        node.last_error = ''
        session.add(node)
        session.commit()
        return {'ok': True, 'status': status}
    except XuiError as exc:
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        return {'ok': False, 'error': str(exc)}


@router.get('/nodes/{node_id}/logs')
def api_node_logs(node_id: int, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    try:
        with XuiClient(node) as xui:
            return {'ok': True, 'logs': xui.server_logs()}
    except XuiError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post('/nodes/{node_id}/restart-xray')
@tracked('Перезапуск Xray')
def api_restart_xray(node_id: int, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    try:
        with XuiClient(node) as xui:
            xui.restart_xray()
        return {'ok': True}
    except XuiError as exc:
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        raise HTTPException(400, str(exc)) from exc


@router.post('/nodes/{node_id}/sync')
@tracked('Синхронизация входов')
def api_sync_node(node_id: int, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    try:
        rows = sync_node(session, node)
        ports = {row.port for row in rows}
        logs = sync_node_firewall(node, ports, session)
        return {'ok': True, 'logs': logs, 'count': len(rows)}
    except XuiError as exc:
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        raise HTTPException(400, str(exc)) from exc


class ProvisionIn(BaseModel):
    template_ids: list[int] = Field(default_factory=list)


@router.post('/nodes/{node_id}/provision')
@tracked('Настройка входов')
def api_provision_node(node_id: int, session: SessionDep, body: ProvisionIn | None = None) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    ids = (body.template_ids if body else None) or []
    if ids:
        templates = session.exec(
            select(InboundTemplate).where(
                InboundTemplate.enabled == True,  # noqa: E712
                InboundTemplate.id.in_(ids),
            )
        ).all()
    else:
        templates = templates_for_node(session, node)
    if not templates:
        raise HTTPException(400, 'На сервере не выбраны входы — отметьте шаблоны в списке «Входы»')
    logs = provision_templates(session, node, templates)
    if not _templates_ok(logs):
        return {'ok': False, 'logs': logs}
    ports = {row.port for row in templates_for_node(session, node)}
    ports.update(row.port for row in templates)
    logs.extend(sync_node_firewall(node, ports, session))
    return {'ok': True, 'logs': logs}


def drop_blank_secrets(data: dict) -> None:
    """Пустой токен, пароль и пользователь не затирают уже сохранённые."""
    for key in ('api_token', 'ssh_password', 'ssh_user'):
        if key in data and not str(data.get(key) or '').strip():
            data.pop(key)


@router.patch('/nodes/{node_id}')
@tracked('Изменение сервера')
def patch_node(node_id: int, body: NodePatch, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    data = body.model_dump(exclude_unset=True)
    drop_blank_secrets(data)
    if data.get('flag'):
        data['flag'] = to_iso(data['flag']) or data['flag']
    if 'panel_url' in data and data['panel_url'] is not None:
        if not str(data['panel_url']).strip() or (node.install_state or '') == 'installing':
            data.pop('panel_url')
        else:
            data['panel_url'] = normalize_panel_url(data['panel_url'])
            try:
                require_panel_transport(data['panel_url'])
            except XuiError as exc:
                raise HTTPException(400, str(exc)) from exc
            if not data.get('public_host'):
                data['public_host'] = public_host_from_url(data['panel_url'])
    if (node.install_state or '') == 'installing':
        data.pop('api_token', None)
    if data.get('enabled') is True and (node.install_kind or '') == 'grafana':
        raise HTTPException(400, 'Grafana не входит в подписку')
    template_ids = data.pop('template_ids', None)
    for key, value in data.items():
        setattr(node, key, value)
    if str(data.get('ssh_password') or '').strip():
        if (node.ssh_auth or '') == 'key':
            node.ssh_auth = 'both'
        elif (node.ssh_auth or '') != 'both':
            node.ssh_auth = 'password'
    session.add(node)
    session.commit()
    session.refresh(node)
    logs: list[str] = []
    if {'ssh_user', 'ssh_port', 'ssh_password'} & set(data):
        if (node.install_state or '') == 'installing':
            logs = [f'{node.name}: файрвол подождёт, пока ставится 3x-ui']
        else:
            ports = {row.port for row in templates_for_node(session, node)}
            logs = sync_node_firewall(node, ports, session)
            session.refresh(node)
    if template_ids is not None and node.id is not None:
        set_node_template_ids(session, node.id, template_ids)
    out = _node_out(node, session)
    out['logs'] = logs
    return out


def _templates_ok(logs: list[str]) -> bool:
    return not any(
        any(marker in line for marker in ('не найден или выключен', 'не записались', 'не записалось',
                                           'не удалён', 'не навесился', 'не создан', 'sync:', 'ошибка связи'))
        for line in logs
    )


@router.post('/nodes/refresh-templates')
@tracked('Сверка входов флота')
def api_refresh_all_templates(session: SessionDep) -> dict:
    logs = reconcile_all_nodes(session)
    return {'ok': _templates_ok(logs), 'logs': logs}


@router.post('/nodes/{node_id}/refresh-templates')
@tracked('Сверка входов сервера')
def api_refresh_node_templates(node_id: int, body: ProvisionIn, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    if 'template_ids' not in body.model_fields_set:
        raise HTTPException(422, 'Для сверки входов явно укажите template_ids')
    try:
        logs = reconcile_node_templates(session, node, body.template_ids)
    except XuiError as exc:
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        raise HTTPException(400, str(exc)) from exc
    return {'ok': _templates_ok(logs), 'logs': logs, 'node': _node_out(node, session)}


@router.post('/nodes/{node_id}/templates')
@tracked('Применение шаблонов')
def api_apply_node_templates(node_id: int, body: ProvisionIn, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    if 'template_ids' not in body.model_fields_set:
        raise HTTPException(422, 'Для изменения входов явно укажите template_ids')
    logs = apply_node_templates(session, node, body.template_ids)
    return {'ok': _templates_ok(logs), 'logs': logs, 'node': _node_out(node, session)}


@router.delete('/nodes/{node_id}')
@tracked('Удаление сервера')
def delete_node(node_id: int, session: SessionDep, wipe_remote: bool = False) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    from app.models import ClientPlacement, MasterOperation, NodePingHour, NodeTemplateAssignment, utcnow

    name = node.name
    warnings = []
    if wipe_remote:
        inbounds = session.exec(select(NodeInbound).where(NodeInbound.node_id == node_id)).all()
        try:
            with XuiClient(node) as xui:
                for inbound in inbounds:
                    try:
                        xui.del_inbound(inbound.xui_inbound_id)
                    except XuiError as exc:
                        warnings.append(f'Вход {inbound.port} не удалён с панели: {exc}')
        except XuiError as exc:
            warnings.append(f'Не удалось подключиться к панели: {exc}')
    try:
        for model in (ClientPlacement, NodeTemplateAssignment, NodePingHour, NodeInbound):
            session.execute(delete(model).where(model.node_id == node_id))
        session.execute(update(MasterOperation).where(MasterOperation.active_key.in_(
            [f'{task}/{node_id}' for task in ('agent', 'install', 'update')]
        )).values(state='warning', detail='Сервер удалён из Master', active_key=None, finished_at=utcnow()))
        session.execute(delete(AppSetting).where(AppSetting.key == credential_key(node_id)))
        session.delete(node)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        detail = 'остались связанные записи' if isinstance(exc, IntegrityError) else 'ошибка записи в базу Master'
        raise HTTPException(409, f'Не удалось удалить «{name}»: {detail}.') from exc
    return {'ok': True, 'logs': warnings} if warnings else {'ok': True}


@router.get('/nodes/{node_id}/inbounds')
def list_inbounds(node_id: int, session: SessionDep) -> list[dict]:
    rows = session.exec(select(NodeInbound).where(NodeInbound.node_id == node_id)).all()
    return [row.model_dump() for row in rows]


@router.patch('/inbounds/{inbound_id}')
@tracked('Изменение входа')
def patch_inbound(inbound_id: int, body: InboundPatch, session: SessionDep) -> dict:
    row = session.get(NodeInbound, inbound_id)
    if not row:
        raise HTTPException(404, 'inbound not found')
    data = body.model_dump(exclude_unset=True)
    push_panel = data.pop('push_panel', body.push_panel)
    names = None
    if 'server_names' in data and data['server_names'] is not None:
        names = split_csv(data['server_names'])
        data['server_names'] = ','.join(names)
    for key, value in data.items():
        setattr(row, key, value)
    session.add(row)
    session.commit()
    session.refresh(row)
    pushed = None
    push_error = ''
    if names is not None and push_panel:
        node = session.get(Node, row.node_id)
        if node:
            try:
                push_server_names(node, row, names)
                pushed = True
            except XuiError as exc:
                pushed = False
                push_error = str(exc)
    out = row.model_dump()
    out['pushed_to_panel'] = pushed
    out['push_error'] = push_error
    return out


class DestSniIn(BaseModel):
    dest: str


class DestScanIn(BaseModel):
    dest: str
    sni: str = ''
    node_ids: list[int] = Field(default_factory=list)


class NeighborScanIn(BaseModel):
    node_id: int


@router.post('/dest-scan')
@tracked('Проверка целей')
def dest_scan(body: DestScanIn, session: SessionDep) -> dict:
    from concurrent.futures import ThreadPoolExecutor

    from app.reality_scan import normalize_target, scan_target_on_node, sort_scans

    try:
        target = normalize_target(body.dest)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    query = select(Node).where(Node.enabled == True)  # noqa: E712
    if body.node_ids:
        query = select(Node).where(Node.id.in_(body.node_ids))
    nodes = session.exec(query.order_by(Node.sort_order, Node.id)).all()
    if not nodes:
        raise HTTPException(400, 'Нет сервера для проверки')
    sni = (body.sni or '').split(',')[0].strip()
    if len(nodes) == 1:
        results = [scan_target_on_node(nodes[0], target, sni)]
    else:
        with ThreadPoolExecutor(max_workers=min(8, len(nodes))) as pool:
            results = list(pool.map(lambda node: scan_target_on_node(node, target, sni), nodes))
    return {'target': target, 'results': sort_scans(results)}


@router.post('/neighbor-scan')
@tracked('Проверка соседних адресов')
def neighbor_scan(body: NeighborScanIn, session: SessionDep) -> dict:
    from app.neighbor_scan import scan_node_neighborhood

    node = session.get(Node, body.node_id)
    if node is None:
        raise HTTPException(404, 'сервер не найден')
    try:
        return scan_node_neighborhood(node)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post('/dest-sni')
@tracked('Проверка SNI')
def dest_sni(body: DestSniIn) -> dict:
    try:
        parse_dest(body.dest)
        return fetch_dest_sni(body.dest)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get('/templates')
def list_templates(session: SessionDep) -> list[dict]:
    return [t.model_dump() for t in session.exec(select(InboundTemplate)).all()]


@router.post('/templates')
@tracked('Создание шаблона')
def create_template(body: TemplateIn, session: SessionDep) -> dict:
    data = body.model_dump()
    data['flags'] = normalize_flags(data.get('flags', ''))
    row = InboundTemplate(**data)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row.model_dump()


@router.put('/templates/{template_id}')
@tracked('Изменение шаблона')
def update_template(template_id: int, body: TemplateIn, session: SessionDep) -> dict:
    row = session.get(InboundTemplate, template_id)
    if not row:
        raise HTTPException(404, 'template not found')
    data = body.model_dump()
    data['flags'] = normalize_flags(data.get('flags', ''))
    for key, value in data.items():
        setattr(row, key, value)
    session.add(row)
    session.commit()
    session.refresh(row)
    logs: list[str] = []
    from app.models import NodeTemplateAssignment

    assignments = session.exec(
        select(NodeTemplateAssignment).where(NodeTemplateAssignment.template_id == row.id)
    ).all()
    for assignment in assignments:
        node = session.get(Node, assignment.node_id)
        if node is None:
            continue
        try:
            logs.extend(sync_template_fields(session, node, [row]))
        except XuiError as exc:
            logs.append(f'{node.name}: имя входа не записалось на панель: {exc}')
    out = row.model_dump()
    out['logs'] = logs
    return out


@router.delete('/templates/{template_id}')
@tracked('Удаление шаблона')
def delete_template(template_id: int, session: SessionDep) -> dict:
    row = session.get(InboundTemplate, template_id)
    if not row:
        raise HTTPException(404)
    if session.exec(select(NodeTemplateAssignment.node_id).where(
        NodeTemplateAssignment.template_id == template_id
    ).limit(1)).first() is not None:
        raise HTTPException(409, 'Сначала снимите шаблон с серверов, на которых он назначен')
    session.delete(row)
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(409, 'Шаблон назначен на сервер') from exc
    return {'ok': True}


def placement_counts(session: Session, client_id: int | None = None) -> dict[int, tuple[int, int]]:
    query = select(ClientPlacement.client_id, func.sum(case((ClientPlacement.ok, 1), else_=0)),
                   func.count()).group_by(ClientPlacement.client_id)
    if client_id is not None:
        query = query.where(ClientPlacement.client_id == client_id)
    return {cid: (ok, total) for cid, ok, total in session.exec(query)}


def _client_out(session, client: Client, counts: dict | None = None) -> dict:
    if counts is None:
        counts = placement_counts(session, client.id)
    ok, total = counts.get(client.id, (0, 0))
    return {
        **client.model_dump(),
        'days_left': days_left(client),
        'sub_url': client_sub_url(client),
        'placements_ok': ok,
        'placements_total': total,
    }


@router.get('/clients')
def list_clients(session: SessionDep) -> list[dict]:
    rows = session.exec(select(Client).order_by(Client.id.desc())).all()
    counts = placement_counts(session)
    return [_client_out(session, c, counts) for c in rows]


def _client_by_cabinet(session: Session, account_id: str) -> Client | None:
    return session.exec(
        select(Client).where(Client.cabinet_account_id == account_id)
    ).first()


def _client_payload(session: Session, client: Client, *, created: bool, logs: list[str]) -> dict:
    return {
        'client': _client_out(session, client),
        'logs': logs,
        'created': created,
    }


@router.get('/clients/by-cabinet/{account_id}')
def get_client_by_cabinet(account_id: str, session: SessionDep) -> dict:
    client = _client_by_cabinet(session, account_id)
    if client is None:
        raise HTTPException(404, 'client not found')
    return _client_payload(session, client, created=False, logs=[])


@router.post('/clients')
@tracked('Выдача доступа')
def create_client(body: ClientIn, session: SessionDep) -> dict:
    account_id = body.cabinet_account_id
    if account_id:
        existing = _client_by_cabinet(session, account_id)
        if existing is not None:
            return _client_payload(session, existing, created=False, logs=[])

    slug_base = slugify(body.name)
    slug = slug_base
    n = 1
    while session.exec(select(Client).where(Client.slug == slug)).first():
        n += 1
        slug = f'{slug_base}{n}'
    client = Client(
        name=body.name.strip(),
        slug=slug,
        uuid=new_uuid(),
        sub_token=new_token(),
        expire_at=expire_from_days(body.days),
        traffic_limit_bytes=body.traffic_gb * 1024 * 1024 * 1024 if body.traffic_gb else 0,
        limit_ip=body.limit_ip,
        note=body.note,
        enable=True,
        cabinet_account_id=account_id,
    )
    session.add(client)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        if account_id:
            existing = _client_by_cabinet(session, account_id)
            if existing is not None:
                return _client_payload(session, existing, created=False, logs=[])
        raise
    session.refresh(client)
    logs = provision_client(session, client)
    return _client_payload(session, client, created=True, logs=logs)


@router.patch('/clients/{client_id}')
@tracked('Изменение доступа')
def patch_client(client_id: int, body: ClientPatch, session: SessionDep) -> dict:
    with client_access_lock(client_id):
        client = session.get(Client, client_id)
        if not client:
            raise HTTPException(404)
        if session.get(AppSetting, f'revoke_client/{client_id}'):
            raise HTTPException(409, 'Не завершён отзыв доступа: повторите удаление')
        if body.name is not None:
            client.name = body.name
        if body.enable is not None:
            client.enable = body.enable
        if body.note is not None:
            client.note = body.note
        if body.limit_ip is not None:
            client.limit_ip = body.limit_ip
        if body.traffic_gb is not None:
            client.traffic_limit_bytes = body.traffic_gb * 1024 * 1024 * 1024
        if body.days is not None:
            client.expire_at = expire_from_days(body.days)
        if body.add_days:
            now = datetime.now(timezone.utc)
            base = client.expire_at or now
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
            if base < now:
                base = now
            client.expire_at = base + timedelta(days=body.add_days)
        session.add(client)
        session.commit()
        logs = provision_client(session, client)
        session.refresh(client)
        return {'client': _client_out(session, client), 'logs': logs}


@router.post('/clients/reconcile')
@tracked('Сверка клиентов')
def reconcile_all_clients(session: SessionDep) -> dict:
    logs = reconcile_clients(session)
    return {'ok': True, 'logs': logs}


@router.post('/clients/{client_id}/provision')
@tracked('Настройка клиента на нодах')
def retry_client(client_id: int, session: SessionDep) -> dict:
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(404)
    logs = provision_client(session, client)
    return {'ok': True, 'logs': logs}


@router.delete('/clients/{client_id}')
@tracked('Удаление клиента')
def api_delete_client(client_id: int, session: SessionDep) -> dict:
    with client_access_lock(client_id):
        client = session.get(Client, client_id)
        if not client:
            raise HTTPException(404)
        ok, logs = delete_client_remote(session, client, remember_pending=True)
        if not ok:
            return {'ok': False, 'logs': logs}
        session.execute(delete(AppSetting).where(AppSetting.key == f'revoke_client/{client_id}'))
        session.execute(delete(ClientPingReport).where(ClientPingReport.client_id == client_id))
        session.delete(client)
        session.commit()
        return {'ok': True, 'logs': logs}


@router.get('/clients/{client_id}/preview')
def preview_client(client_id: int, session: SessionDep) -> dict:
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(404)
    return {'yaml': render_profile(session, client)}


@router.get('/config')
def get_config(session: SessionDep) -> dict:
    doc = session.exec(select(ConfigDoc)).first()
    if not doc:
        raise HTTPException(404)
    return doc.model_dump()


@router.put('/config')
@tracked('Сохранение профиля Clash')
def put_config(body: ConfigIn, session: SessionDep) -> dict:
    from app.models import utcnow

    doc = session.exec(select(ConfigDoc)).first()
    if not doc:
        doc = ConfigDoc(yaml_text=body.yaml_text)
        session.add(doc)
    else:
        doc.yaml_text = body.yaml_text
        if body.pool_group_names is not None:
            doc.pool_group_names = body.pool_group_names
        if body.global_extra_snis is not None:
            doc.global_extra_snis = body.global_extra_snis
        doc.updated_at = utcnow()
        session.add(doc)
    session.commit()
    session.refresh(doc)
    return doc.model_dump()


@router.get('/site')
def site_metrics(session: SessionDep, span: str = '24h') -> dict:
    from app.site_traffic import RANGES, ingest_access_log, site_series

    if span not in RANGES:
        raise HTTPException(400, 'unknown span')
    ingest_access_log(session)
    return site_series(session, span)


@router.get('/stats')
def stats(session: SessionDep) -> dict:
    nodes = session.exec(select(Node)).all()
    clients = session.exec(select(Client)).all()
    return {
        'nodes': len(nodes),
        'nodes_enabled': sum(1 for n in nodes if n.enabled),
        'clients': len(clients),
        'clients_active': sum(1 for c in clients if not is_expired(c)),
        'expiring': [
            {'id': c.id, 'name': c.name, 'days_left': days_left(c)}
            for c in clients
            if c.expire_at and not is_expired(c) and days_left(c).isdigit() and int(days_left(c)) <= 7
        ],
    }


@router.get('/overview')
def overview(session: SessionDep, refresh_versions: bool = False) -> dict:
    nodes = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    clients = session.exec(select(Client).order_by(Client.id.desc())).all()
    inbound_counts = fleet_inbound_counts(session)
    assignments = fleet_template_ids(session)
    counts = placement_counts(session)
    probes = probe_nodes([node for node in nodes if node.enabled and not node.is_grafana()], refresh_versions)
    node_out = []
    for node in nodes:
        if not node.enabled:
            node_out.append(
                {
                    **_node_out(node, assignments=assignments),
                    'online': False,
                    'cpu': None,
                    'mem_used': None,
                    'mem_total': None,
                    'uptime': None,
                    'xray': '',
                    'tcp': None,
                    'udp': None,
                    'inbound_count': inbound_counts.get(node.id, 0),
                    'probe_error': '',
                }
            )
            continue
        probe = probes.get(node.id or 0) or {}
        online = bool(probe.get('online'))
        if online:
            node.last_error = ''
        elif probe.get('error'):
            node.last_error = str(probe.get('error'))[:500]
        session.add(node)
        st = probe.get('status') or {}
        store_probe(node, probe)
        node_out.append(
            {
                **_node_out(node, assignments=assignments),
                'online': online,
                'cpu': st.get('cpu'),
                'mem_used': st.get('mem_used'),
                'mem_total': st.get('mem_total'),
                'uptime': st.get('uptime'),
                'xray': st.get('xray'),
                # Свежие версии с панели; в БД лежит последнее увиденное (на случай,
                # когда панель этого релиза версию не отдаёт).
                'xui_version': node.xui_version or '',
                'xray_version': st.get('xray_version') or (node.xray_version or ''),
                'version_checked_at': _as_utc(node.version_checked_at).isoformat() if node.version_checked_at else None,
                'tcp': st.get('tcp'),
                'udp': st.get('udp'),
                'inbound_count': probe.get('inbound_count', 0) if online else inbound_counts.get(node.id, 0),
                'probe_error': probe.get('error') or '',
            }
        )

    client_out = []
    for client in clients:
        usage = aggregate_client_usage(client, nodes, probes)
        remember_last_online(session, client, usage['last_online'])
        limit = client.traffic_limit_bytes or 0
        client_out.append(
            {
                **_client_out(session, client, counts),
                'expired': is_expired(client),
                'up': usage['up'],
                'down': usage['down'],
                'used': usage['used'],
                'used_label': format_bytes(usage['used']),
                'limit_label': format_bytes(limit) if limit else 'без лимита',
                'online_nodes': usage['online_nodes'],
                'last_online': usage['last_online'],
                'seen_on_nodes': usage['seen_on_nodes'],
            }
        )
    session.commit()
    return {'nodes': node_out, 'clients': client_out}


def _as_utc(value: datetime) -> datetime:
    """SQLite отдаёт дату без часового пояса — считаем её UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@router.get('/presence')
def presence(session: SessionDep) -> dict:
    nodes = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    clients = session.exec(select(Client).order_by(Client.id.desc())).all()
    probes = probe_nodes_presence([node for node in nodes if node.enabled])
    client_out = []
    for client in clients:
        usage = aggregate_client_usage(client, nodes, probes)
        remember_last_online(session, client, usage['last_online'])
        limit = client.traffic_limit_bytes or 0
        client_out.append(
            {
                'id': client.id,
                'online_nodes': usage['online_nodes'],
                'last_online': usage['last_online'],
                'used': usage['used'],
                'used_label': format_bytes(usage['used']),
                'limit_label': format_bytes(limit) if limit else 'без лимита',
            }
        )
    session.commit()
    return {'clients': client_out}


def _guard_nodes(session: SessionDep, install: bool) -> dict:
    """Снять состояние защиты со всех машин одним проходом.

    Счётчик «в бане» приходит в том же снимке, что состояние и баны за сутки:
    вкладка рисует столбцы из этого ответа, не дожидаясь клика по серверу.
    """
    engine = session.get_bind()
    from app.util import run_parallel

    nodes = [
        node for node in session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
        if not node.is_grafana()
    ]
    node_ids = [node.id for node in nodes if node.id is not None]

    def run(node_id: int):
        with Session(engine) as local:
            node = local.get(Node, node_id)
            if node is None or node.is_grafana():
                return [], None
            logs = sync_node_guard(node, local, install=install)
            view = guard_snapshot(node)
            view['ok'] = view['state'] == 'protecting' if install else view['state'] not in {'error', 'no_ssh'}
            return logs, view

    result = _fleet_result(node_ids, run_parallel(node_ids, run))
    return {**result, **guard_totals(result['nodes'])}


class AdoptIn(BaseModel):
    ssh_user: str = ''
    ssh_port: int = 0
    ssh_password: str = ''


def _apply_adopt_hint(node: Node, body: AdoptIn) -> None:
    if (body.ssh_user or '').strip():
        node.ssh_user = body.ssh_user.strip()
    if body.ssh_port:
        node.ssh_port = int(body.ssh_port)
    if (body.ssh_password or '').strip():
        node.ssh_password = body.ssh_password.strip()
        if (node.ssh_auth or '') == 'key':
            node.ssh_auth = 'both'
        elif (node.ssh_auth or '') != 'both':
            node.ssh_auth = 'password'


@router.post('/nodes/{node_id}/adopt-key')
@tracked('Настройка SSH')
def adopt_node_key(node_id: int, body: AdoptIn, session: SessionDep) -> dict:
    from app.ssh_access import adopt_node as adopt_ssh

    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    _apply_adopt_hint(node, body)
    session.add(node)
    session.commit()
    result = adopt_ssh(node, session)
    session.refresh(node)
    return {
        'ok': result.ok,
        'logs': result.logs,
        'id': node.id,
        'ssh_auth': result.auth,
    }


@router.post('/protection/adopt')
@tracked('Настройка SSH флота')
def adopt_protection(session: SessionDep) -> dict:
    engine = session.get_bind()
    from app.ssh_access import adopt_node as adopt_ssh
    from app.util import run_parallel

    nodes = [
        node for node in session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
        if not node.is_grafana()
    ]
    node_ids = [node.id for node in nodes if node.id is not None]

    def run(node_id: int):
        with Session(engine) as local:
            node = local.get(Node, node_id)
            if node is None or node.is_grafana():
                return [], None
            result = adopt_ssh(node, local)
            return result.logs, {'id': node.id, 'ssh_auth': node.ssh_auth or result.auth, 'ok': result.ok}

    return _fleet_result(node_ids, run_parallel(node_ids, run))


@router.post('/protection/ports')
@tracked('Обновление правил портов')
def sync_ports(session: SessionDep) -> dict:
    """Записать правило портов в ufw и выключить подписку 3x-ui на всём флоте."""
    engine = session.get_bind()
    from app.models import NodeInbound
    from app.provision import disable_node_subscription
    from app.util import run_parallel

    nodes = [
        node for node in session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
        if not node.is_grafana()
    ]
    node_ids = [node.id for node in nodes if node.id is not None]

    def run(node_id: int):
        with Session(engine) as local:
            node = local.get(Node, node_id)
            if node is None or node.is_grafana():
                return [], None
            logs: list[str] = []
            subscription_off = True
            try:
                logs.append(disable_node_subscription(node))
            except Exception as exc:
                subscription_off = False
                logs.append(f'{node.name}: подписку 3x-ui не выключить: {exc}')
            inbound_ports = {
                int(row.port)
                for row in local.exec(select(NodeInbound).where(NodeInbound.node_id == node.id)).all()
                if int(row.port or 0) > 0
            }
            logs.extend(sync_node_firewall(node, inbound_ports, local))
            local.refresh(node)
            return logs, {
                'id': node.id,
                'firewall_on': bool(node.firewall_on),
                'ok': subscription_off and bool(node.firewall_on),
                'note': node.firewall_note or '',
            }

    return _fleet_result(node_ids, run_parallel(node_ids, run))


def _fleet_result(node_ids, results) -> dict:
    logs, views = [], []
    ok = True
    for node_id, result in zip(node_ids, results):
        if isinstance(result, Exception):
            logs.append(f'Нода {node_id}: {type(result).__name__}')
            ok = False
            continue
        steps, view = result
        logs.extend(steps)
        if view is None:
            logs.append(f'Нода {node_id} исчезла во время операции')
            ok = False
        else:
            views.append(view)
            ok = ok and view['ok']
    return {'ok': ok, 'logs': logs, 'nodes': views}


@router.post('/protection/refresh')
@tracked('Проверка защиты')
def refresh_protection(session: SessionDep) -> dict:
    return _guard_nodes(session, install=False)


@router.post('/protection/install')
@tracked('Установка защиты')
def install_protection(session: SessionDep) -> dict:
    return _guard_nodes(session, install=True)


@router.get('/nodes/{node_id}/bans')
def node_bans(node_id: int, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    try:
        view, bans = read_bans(node)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    _remember(node, session, GuardView(view.state, view.banned, view.day, view.note, view.installed))
    return {
        'state': view.state,
        'note': view.note,
        'banned': view.banned,
        'day': view.day,
        'bans': [
            {
                'ip': row.ip,
                'jail': row.jail,
                'reason': row.reason,
                'failures': row.failures,
                'times': row.times,
                'until': row.until,
            }
            for row in bans
        ],
    }


class UnbanIn(BaseModel):
    ip: str = ''
    all: bool = False


@router.post('/nodes/{node_id}/unban')
@tracked('Снятие блокировки')
def node_unban(node_id: int, body: UnbanIn, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    try:
        logs = unban(node, body.ip, body.all)
        view, bans = read_bans(node)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    _remember(node, session, GuardView(view.state, view.banned, view.day, view.note))
    return {
        'ok': True,
        'logs': logs,
        'state': view.state,
        'note': view.note,
        'banned': view.banned,
        'day': view.day,
        'bans': [
            {
                'ip': row.ip,
                'reason': row.reason,
                'failures': row.failures,
                'times': row.times,
                'until': row.until,
            }
            for row in bans
        ],
    }


@router.delete('/releases/{filename}')
@tracked('Удаление релиза')
def delete_release(filename: str) -> dict:
    return delete_installer(filename)
