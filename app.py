"""
app.py - CISP Governance (versão melhorada)
Melhorias: login em página única, permissões refinadas, dashboard Altair,
integração PostgreSQL (SQLAlchemy), audit logs, animação CSS simples.
"""

import os
from datetime import datetime, date, time
from functools import wraps
import hashlib
import json

import streamlit as st
import pandas as pd
import altair as alt
from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, String, Text,
    Date, DateTime, Boolean, ForeignKey, inspect
)
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import select, func
from dotenv import load_dotenv
import bcrypt

load_dotenv()

# --------------------------
# CONFIGURAÇÃO DO BANCO
# --------------------------
DATABASE_URL = os.getenv("DATABASE_URL")  # e.g. postgresql+psycopg2://user:pass@host:5432/db
USE_SQLITE_FALLBACK = False

if DATABASE_URL:
    engine = create_engine(DATABASE_URL, echo=False, future=True)
else:
    USE_SQLITE_FALLBACK = True
    engine = create_engine("sqlite:///cisp_gov.db", echo=False, future=True)

metadata = MetaData()

# ---------- tabelas ----------
users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, unique=True, nullable=False),
    Column("password_hash", String, nullable=False),
    Column("role", String, nullable=False),  # admin, gestor, analista, auditor
    Column("full_name", String, nullable=True),
)

policies = Table(
    "policies", metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String, nullable=False),
    Column("version", String, nullable=False),
    Column("owner", String, nullable=False),
    Column("classification", String, nullable=False),
    Column("scope", Text),
    Column("status", String, nullable=False),
    Column("effective_date", Date),
    Column("next_review_date", Date),
    Column("body", Text),
    Column("created_at", DateTime, default=func.now()),
    Column("updated_at", DateTime, default=func.now()),
)

assets = Table(
    "assets", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("type", String, nullable=False),
    Column("owner", String, nullable=False),
    Column("criticality", String, nullable=False),
)

risks = Table(
    "risks", metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String, nullable=False),
    Column("description", Text),
    Column("asset_id", Integer, ForeignKey("assets.id"), nullable=True),
    Column("category", String),
    Column("likelihood", Integer),
    Column("impact", Integer),
    Column("inherent", Integer),
    Column("controls", Text),
    Column("residual", Integer),
    Column("owner", String),
    Column("status", String),
    Column("review_date", Date),
    Column("created_at", DateTime, default=func.now()),
)

incidents = Table(
    "incidents", metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String, nullable=False),
    Column("severity", String),
    Column("category", String),
    Column("detected_at", DateTime),
    Column("contained_at", DateTime, nullable=True),
    Column("eradicated_at", DateTime, nullable=True),
    Column("recovered_at", DateTime, nullable=True),
    Column("status", String),
    Column("description", Text),
    Column("root_cause", Text),
    Column("lessons_learned", Text),
    Column("notification_required", Boolean, default=False),
    Column("notified_at", DateTime, nullable=True),
    Column("created_at", DateTime, default=func.now()),
)

dsar = Table(
    "dsar", metadata,
    Column("id", Integer, primary_key=True),
    Column("requester", String),
    Column("type", String),
    Column("received_date", Date),
    Column("due_date", Date),
    Column("status", String),
    Column("notes", Text),
)

audits = Table(
    "audits", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String),
    Column("audit_date", Date),
    Column("scope", Text),
    Column("findings", Text),
    Column("status", String),
)

trainings = Table(
    "trainings", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String),
    Column("audience", String),
    Column("start_date", Date),
    Column("end_date", Date),
    Column("status", String),
)

audit_logs = Table(
    "audit_logs", metadata,
    Column("id", Integer, primary_key=True),
    Column("actor", String),
    Column("role", String),
    Column("action", String),
    Column("target_table", String),
    Column("target_id", Integer, nullable=True),
    Column("details", Text, nullable=True),
    Column("created_at", DateTime, default=func.now()),
)

# --------------------------
# BOOTSTRAP DAS TABELAS E ADMIN DEFAULT
# --------------------------
def bootstrap():
    inspector = inspect(engine)
    try:
        metadata.create_all(engine)
    except OperationalError as e:
        st.error(f"Erro ao criar tabelas: {e}")
        return

    # criar admin se não existir
    with engine.connect() as conn:
        exists = conn.execute(select(users.c.id).where(users.c.username == "admin")).first()
        if not exists:
            pw = hash_password("admin123")
            conn.execute(users.insert().values(username="admin", password_hash=pw, role="admin", full_name="Administrador"))
            conn.commit()

# --------------------------
# UTILITÁRIOS DE SEGURANÇA
# --------------------------
def hash_password(password: str) -> str:
    pw = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw, salt).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

def log_action(actor, role, action, target_table=None, target_id=None, details=None):
    with engine.connect() as conn:
        conn.execute(
            audit_logs.insert().values(
                actor=actor, role=role, action=action,
                target_table=target_table, target_id=target_id, details=details, created_at=datetime.utcnow()
            )
        )
        conn.commit()

def require_roles(allowed):
    """decorator para checar permissões antes de executar funções de UI que alteram dados"""
    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = st.session_state.get("user")
            if not user:
                st.error("Acesso negado: usuário não autenticado.")
                return
            if user["role"] == "admin":
                return func(*args, **kwargs)
            if user["role"] in allowed:
                return func(*args, **kwargs)
            st.warning("Permissão negada para o seu perfil.")
        return wrapper
    return deco

# --------------------------
# AUTENTICAÇÃO (LOGIN PÁGINA ÚNICA)
# --------------------------
def login_ui():
    st.markdown(
        """
        <style>
        .bg {
            background: linear-gradient(135deg,#0f1724 0%, #071426 100%);
            height: 220px;
            border-radius: 12px;
            padding: 18px;
            color: white;
            margin-bottom: 18px;
        }
        .card {
            background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
            padding: 18px;
            border-radius: 10px;
            box-shadow: 0 6px 18px rgba(0,0,0,0.25);
        }
        .pulse {
            display:inline-block;
            width:14px;height:14px;
            border-radius:14px;
            background: #2bd37b;
            box-shadow: 0 0 0 rgba(43,211,123, .7);
            -webkit-animation: pulse 1.8s infinite;
            animation: pulse 1.8s infinite;
            margin-right:8px;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(43,211,123, .7); }
            70% { box-shadow: 0 0 0 10px rgba(43,211,123, 0); }
            100% { box-shadow: 0 0 0 0 rgba(43,211,123, 0); }
        }
        </style>
        """,
        unsafe_allow_html=True
    )
    st.markdown('<div class="bg"><span class="pulse"></span><strong>🔐 CISP — Plataforma de Governança</strong><div style="font-size:12px;margin-top:6px;">Segurança, Riscos e Proteção de Dados</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="card">', unsafe_allow_html=True)
    with st.form("login_form", clear_on_submit=False):
        col1, col2 = st.columns([2, 1])
        username = col1.text_input("Usuário")
        password = col2.text_input("Senha", type="password")
        submitted = st.form_submit_button("Entrar")
        if submitted:
            with engine.connect() as conn:
                row = conn.execute(select(users.c.id, users.c.username, users.c.password_hash, users.c.role, users.c.full_name).where(users.c.username == username)).first()
            if row and verify_password(password, row.password_hash):
                st.session_state["user"] = {"id": row.id, "username": row.username, "role": row.role, "full_name": row.full_name}
                log_action(row.username, row.role, "login", details="Login bem-sucedido")
                st.rerun()
            else:
                st.error("Usuário ou senha inválidos")
    st.markdown('</div>', unsafe_allow_html=True)

# --------------------------
# PÁGINA PRINCIPAL / NAV
# --------------------------
def nav_bar():
    user = st.session_state.get("user")
    st.markdown(f"**Usuário:** {user['full_name'] or user['username']} — Perfil: **{user['role']}**")
    c1, c2, c3 = st.columns([6,2,1])
    with c3:
        if st.button("Sair"):
            log_action(user["username"], user["role"], "logout")
            del st.session_state["user"]
            st.rerun()

    # construção de menu baseada em role
    base_pages = [
        ("Dashboard", page_dashboard),
        ("Ativos & Riscos", page_assets_risks),
        ("Incidentes", page_incidents),
        ("Proteção de Dados", page_privacy),
        ("Auditorias", page_audits),
        ("Treinamentos", page_trainings),
    ]
    # políticas só para admin e gestor (analista não vê políticas)
    pages = []
    for name, func in base_pages:
        if name == "Proteção de Dados":
            # auditor só vê Auditorias e Incidentes - mas ainda permitimos Proteção de Dados para gestor/analista/admin
            if user["role"] == "auditor":
                continue
        pages.append((name, func))

    # adicionar Políticas apenas para admin e gestor
    if user["role"] in ("admin", "gestor"):
        pages.insert(1, ("Políticas", page_policies))

    # auditor só vê Auditorias e Incidentes
    if user["role"] == "auditor":
        pages = [("Incidentes", page_incidents), ("Auditorias", page_audits)]

    # gestor vê tudo exceto Administração; admin verá Administração depois
    if user["role"] == "admin":
        pages.append(("Administração", page_admin))

    menu = [p[0] for p in pages]
    choice = st.selectbox("Navegação", menu)
    for name, func in pages:
        if name == choice:
            func()
            break

# --------------------------
# PÁGINAS / FUNCIONALIDADES
# --------------------------
def page_dashboard():
    st.header("📊 Painel / Dashboard")
    # indicadores gerais
    with engine.connect() as conn:
        pol_count = conn.execute(select(func.count()).select_from(policies)).scalar()
        risk_count = conn.execute(select(func.count()).select_from(risks)).scalar()
        inc_count = conn.execute(select(func.count()).select_from(incidents)).scalar()
        dsar_count = conn.execute(select(func.count()).select_from(dsar)).scalar()

        # riscos para matriz
        risk_rows = pd.read_sql(select(risks), conn)
        inc_rows = pd.read_sql(select(incidents), conn)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Políticas", pol_count or 0)
    col2.metric("Riscos", risk_count or 0)
    col3.metric("Incidentes", inc_count or 0)
    col4.metric("Solicitações (DSAR)", dsar_count or 0)

    st.markdown("### Matriz de Risco (probabilidade x impacto)")
    if risk_rows.empty:
        st.info("Não há riscos cadastrados")
    else:
        # preparar dados
        risk_rows["likelihood"] = risk_rows["likelihood"].astype(int)
        risk_rows["impact"] = risk_rows["impact"].astype(int)
        risk_rows["size"] = risk_rows["residual"].fillna(1).astype(int)
        chart = alt.Chart(risk_rows).mark_circle().encode(
            x=alt.X("likelihood:Q", scale=alt.Scale(domain=(0.8,5.2))),
            y=alt.Y("impact:Q", scale=alt.Scale(domain=(0.8,5.2))),
            size=alt.Size("size:Q", title="Risco Residual"),
            color=alt.Color("status:N", title="Status"),
            tooltip=["id","title","owner","controls","residual"]
        ).properties(height=380)
        st.altair_chart(chart, use_container_width=True)

    st.markdown("### Severidade dos incidentes")
    if inc_rows.empty:
        st.info("Sem incidentes registrados")
    else:
        df = inc_rows.copy()
        df["severity"] = df["severity"].fillna("Desconhecida")
        cnt = df.groupby("severity").size().reset_index(name="count")
        bar = alt.Chart(cnt).mark_bar().encode(x="severity:N", y="count:Q", tooltip=["severity","count"])
        st.altair_chart(bar, use_container_width=True)

    st.divider()
    st.markdown("#### Ações rápidas")
    c1, c2, c3 = st.columns(3)
    if c1.button("Novo Risco"):
        st.session_state["_open_tab"] = "risks_new"
        st.rerun()
    if c2.button("Novo Incidente"):
        st.session_state["_open_tab"] = "incidents_new"
        st.rerun()
    if c3.button("Registrar DSAR"):
        st.session_state["_open_tab"] = "dsar_new"
        st.rerun()

# --------------------------
# POLICIES PAGE
# --------------------------
@require_roles(("gestor",))  # allow gestor and admin via decorator logic
def page_policies():
    st.header("📘 Políticas")
    with engine.connect() as conn:
        df = pd.read_sql(select(policies), conn)
    st.dataframe(df[["id","title","version","owner","status","effective_date","next_review_date"]].sort_values("updated_at", ascending=False), use_container_width=True)

    with st.expander("Criar nova política"):
        with st.form("policy_create"):
            title = st.text_input("Título")
            version = st.text_input("Versão", "1.0")
            owner = st.text_input("Responsável", st.session_state["user"]["full_name"] or st.session_state["user"]["username"])
            classification = st.selectbox("Classificação", ["Interna","Restrita","Pública"])
            scope = st.text_area("Escopo", "Todos os colaboradores e sistemas")
            status = st.selectbox("Status", ["Rascunho","Aprovada","Obsoleta"])
            eff = st.date_input("Vigência", value=date.today())
            next_rev = st.date_input("Próxima revisão", value=date(date.today().year+1, date.today().month, date.today().day))
            body = st.text_area("Conteúdo", value="(Insira o texto da política)", height=200)
            submitted = st.form_submit_button("Salvar política")
            if submitted:
                with engine.connect() as conn:
                    res = conn.execute(policies.insert().values(
                        title=title, version=version, owner=owner, classification=classification,
                        scope=scope, status=status, effective_date=eff, next_review_date=next_rev, body=body, created_at=datetime.utcnow(), updated_at=datetime.utcnow()
                    ))
                    conn.commit()
                    new_id = res.inserted_primary_key[0]
                log_action(st.session_state["user"]["username"], st.session_state["user"]["role"], "create_policy", "policies", new_id, details=title)
                st.success("Política criada")

# --------------------------
# ATIVOS E RISCOS
# --------------------------
@require_roles(("analista","gestor"))
def page_assets_risks():
    st.header("🗂️ Ativos e Riscos")
    tab = st.tabs(["Ativos","Riscos","Importar Exemplo"])[0]  # simplified tabs usage pattern
    # Ativos
    with engine.connect() as conn:
        assets_df = pd.read_sql(select(assets), conn)
    st.subheader("Ativos")
    st.dataframe(assets_df, use_container_width=True)
    with st.form("asset_create"):
        name = st.text_input("Nome do ativo")
        atype = st.selectbox("Tipo", ["Informação","Aplicação","Infraestrutura","Físico","Pessoa"])
        owner = st.text_input("Responsável")
        criticality = st.selectbox("Criticidade", ["Baixa","Média","Alta","Crítica"])
        submitted = st.form_submit_button("Adicionar Ativo")
        if submitted:
            with engine.connect() as conn:
                res = conn.execute(assets.insert().values(name=name, type=atype, owner=owner, criticality=criticality))
                conn.commit()
                new_id = res.inserted_primary_key[0]
            log_action(st.session_state["user"]["username"], st.session_state["user"]["role"], "create_asset", "assets", new_id, details=name)
            st.success("Ativo adicionado")

    st.divider()
    # Riscos
    with engine.connect() as conn:
        risks_df = pd.read_sql(select(risks), conn)
    st.subheader("Riscos")
    st.dataframe(risks_df, use_container_width=True)
    with st.form("risk_create"):
        title = st.text_input("Título do risco")
        description = st.text_area("Descrição")
        # assets select
        with engine.connect() as conn:
            asset_options = pd.read_sql(select(assets.c.id, assets.c.name), conn)
        asset_choice = st.selectbox("Ativo (opcional)", ["Nenhum"] + asset_options["name"].tolist())
        asset_id = None
        if asset_choice != "Nenhum" and not asset_options.empty:
            asset_id = int(asset_options[asset_options["name"] == asset_choice].id.iloc[0])
        category = st.selectbox("Categoria", ["Cibernético","Operacional","Físico","Terceiros","Compliance"])
        likelihood = st.slider("Probabilidade (1-5)", 1, 5, 3)
        impact = st.slider("Impacto (1-5)", 1, 5, 3)
        inherent = likelihood * impact
        controls = st.text_area("Controles aplicados")
        residual = st.slider("Risco residual (1-25)", 1, 25, inherent)
        owner = st.text_input("Responsável pelo risco")
        status = st.selectbox("Status", ["Aberto","Mitigando","Aceito","Transferido","Encerrado"])
        review_date = st.date_input("Data de revisão", value=date.today())
        submitted = st.form_submit_button("Registrar Risco")
        if submitted:
            with engine.connect() as conn:
                res = conn.execute(risks.insert().values(
                    title=title, description=description, asset_id=asset_id, category=category,
                    likelihood=likelihood, impact=impact, inherent=inherent, controls=controls,
                    residual=residual, owner=owner, status=status, review_date=review_date, created_at=datetime.utcnow()
                ))
                conn.commit()
                new_id = res.inserted_primary_key[0]
            log_action(st.session_state["user"]["username"], st.session_state["user"]["role"], "create_risk", "risks", new_id, details=title)
            st.success("Risco registrado")

# --------------------------
# INCIDENTS
# --------------------------
@require_roles(("analista","gestor","auditor"))
def page_incidents():
    st.header("🚨 Incidentes")
    with engine.connect() as conn:
        df = pd.read_sql(select(incidents), conn)
    st.dataframe(df.sort_values("detected_at", ascending=False), use_container_width=True)

    with st.expander("Registrar novo incidente"):
        with st.form("inc_form"):
            title = st.text_input("Título")
            severity = st.selectbox("Severidade", ["Baixa","Média","Alta","Crítica"])
            category = st.selectbox("Categoria", ["Dados Pessoais","Malware","Disponibilidade","Acesso Indevido","Outros"])
            # date + time inputs combinados
            detected_date = st.date_input("Data de detecção", value=date.today())
            detected_time = st.time_input("Hora de detecção", value=datetime.now().time())
            detected_at = datetime.combine(detected_date, detected_time)
            status = st.selectbox("Status", ["Aberto","Contido","Erradicado","Recuperado","Encerrado"], index=0)
            description = st.text_area("Descrição")
            root_cause = st.text_area("Causa raiz")
            lessons = st.text_area("Lições aprendidas")
            notification_required = st.checkbox("Requer notificação à autoridade/titulares")
            notified_at = None
            if notification_required:
                n_date = st.date_input("Data de notificação", value=date.today())
                n_time = st.time_input("Hora de notificação", value=datetime.now().time())
                notified_at = datetime.combine(n_date, n_time)
            submitted = st.form_submit_button("Registrar incidente")
            if submitted:
                with engine.connect() as conn:
                    res = conn.execute(incidents.insert().values(
                        title=title, severity=severity, category=category,
                        detected_at=detected_at, status=status, description=description,
                        root_cause=root_cause, lessons_learned=lessons,
                        notification_required=bool(notification_required), notified_at=notified_at, created_at=datetime.utcnow()
                    ))
                    conn.commit()
                    new_id = res.inserted_primary_key[0]
                log_action(st.session_state["user"]["username"], st.session_state["user"]["role"], "create_incident", "incidents", new_id, details=title)
                st.success("Incidente registrado")

# --------------------------
# PRIVACY (DSAR), AUDITS, TRAININGS
# --------------------------
@require_roles(("gestor","analista"))
def page_privacy():
    st.header("📄 Proteção de Dados — DSAR")
    with engine.connect() as conn:
        df = pd.read_sql(select(dsar), conn)
    st.dataframe(df, use_container_width=True)
    with st.form("dsar_form"):
        requester = st.text_input("Titular")
        dtype = st.selectbox("Tipo", ["Acesso","Correção","Exclusão","Portabilidade","Oposição"])
        received = st.date_input("Recebido em", value=date.today())
        due = st.date_input("Prazo (resposta)", value=date.today())
        status = st.selectbox("Status", ["Aberto","Em Análise","Respondido","Encerrado","Indeferido"])
        notes = st.text_area("Observações")
        submitted = st.form_submit_button("Registrar solicitação")
        if submitted:
            with engine.connect() as conn:
                res = conn.execute(dsar.insert().values(
                    requester=requester, type=dtype, received_date=received, due_date=due, status=status, notes=notes
                ))
                conn.commit()
                new_id = res.inserted_primary_key[0]
            log_action(st.session_state["user"]["username"], st.session_state["user"]["role"], "create_dsar", "dsar", new_id, details=requester)
            st.success("Solicitação registrada")

@require_roles(("auditor","gestor","admin"))
def page_audits():
    st.header("🔍 Auditorias")
    with engine.connect() as conn:
        df = pd.read_sql(select(audits), conn)
    st.dataframe(df, use_container_width=True)
    with st.form("audit_form"):
        name = st.text_input("Nome da auditoria")
        adate = st.date_input("Data", value=date.today())
        scope = st.text_area("Escopo")
        findings = st.text_area("Achados")
        status = st.selectbox("Status", ["Planejada","Em Execução","Concluída"])
        submitted = st.form_submit_button("Registrar auditoria")
        if submitted:
            with engine.connect() as conn:
                res = conn.execute(audits.insert().values(name=name, audit_date=adate, scope=scope, findings=findings, status=status))
                conn.commit()
                new_id = res.inserted_primary_key[0]
            log_action(st.session_state["user"]["username"], st.session_state["user"]["role"], "create_audit", "audits", new_id, details=name)
            st.success("Auditoria registrada")

@require_roles(("gestor","analista"))
def page_trainings():
    st.header("🎓 Treinamentos")
    with engine.connect() as conn:
        df = pd.read_sql(select(trainings), conn)
    st.dataframe(df, use_container_width=True)
    with st.form("training_form"):
        name = st.text_input("Treinamento")
        audience = st.text_input("Público")
        start_date = st.date_input("Início", value=date.today())
        end_date = st.date_input("Término", value=date.today())
        status = st.selectbox("Status", ["Planejada","Em Andamento","Concluída"])
        submitted = st.form_submit_button("Registrar treinamento")
        if submitted:
            with engine.connect() as conn:
                res = conn.execute(trainings.insert().values(name=name, audience=audience, start_date=start_date, end_date=end_date, status=status))
                conn.commit()
                new_id = res.inserted_primary_key[0]
            log_action(st.session_state["user"]["username"], st.session_state["user"]["role"], "create_training", "trainings", new_id, details=name)
            st.success("Treinamento registrado")

# --------------------------
# ADMIN (apenas admin)
# --------------------------
@require_roles(("admin",))
def page_admin():
    st.header("⚙️ Administração do Sistema")
    with engine.connect() as conn:
        users_df = pd.read_sql(select(users.c.id, users.c.username, users.c.role, users.c.full_name), conn)
    st.subheader("Usuários")
    st.dataframe(users_df, use_container_width=True)

    with st.form("create_user"):
        username = st.text_input("Login")
        fullname = st.text_input("Nome completo")
        password = st.text_input("Senha", type="password")
        role = st.selectbox("Perfil", ["admin","gestor","analista","auditor"])
        submitted = st.form_submit_button("Criar usuário")
        if submitted:
            with engine.connect() as conn:
                res = conn.execute(users.insert().values(username=username, password_hash=hash_password(password), role=role, full_name=fullname))
                conn.commit()
                new_id = res.inserted_primary_key[0]
            log_action(st.session_state["user"]["username"], st.session_state["user"]["role"], "create_user", "users", new_id, details=username)
            st.success("Usuário criado")

    st.divider()
    st.subheader("Logs de Auditoria (últimas 200 ações)")
    with engine.connect() as conn:
        logs = pd.read_sql(select(audit_logs).order_by(audit_logs.c.created_at.desc()).limit(200), conn)
    st.dataframe(logs, use_container_width=True)

# --------------------------
# APLICAÇÃO MAIN
# --------------------------
def main():
    st.set_page_config(page_title="CISP Governance", layout="wide", page_icon="🛡️")
    bootstrap()
    if "user" not in st.session_state:
        st.session_state["user"] = None

    if not st.session_state["user"]:
        login_ui()
    else:
        nav_bar()

if __name__ == "__main__":
    main()
