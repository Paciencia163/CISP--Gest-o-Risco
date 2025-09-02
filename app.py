import sqlite3
from contextlib import contextmanager
from datetime import datetime, date
from io import BytesIO
import hashlib
import pandas as pd
import altair as alt
import streamlit as st

DB_PATH = "cisp_gov.db"

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def bootstrap():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','gestor','analista','auditor'))
            );
            CREATE TABLE IF NOT EXISTS policies(
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                version TEXT NOT NULL,
                owner TEXT NOT NULL,
                classification TEXT NOT NULL,
                scope TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('Rascunho','Aprovada','Obsoleta')),
                effective_date DATE,
                next_review_date DATE,
                body TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assets(
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                owner TEXT NOT NULL,
                criticality TEXT NOT NULL CHECK(criticality IN ('Baixa','Média','Alta','Crítica'))
            );
            CREATE TABLE IF NOT EXISTS risks(
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                category TEXT NOT NULL,
                likelihood INTEGER NOT NULL CHECK(likelihood BETWEEN 1 AND 5),
                impact INTEGER NOT NULL CHECK(impact BETWEEN 1 AND 5),
                inherent INTEGER NOT NULL,
                controls TEXT,
                residual INTEGER NOT NULL,
                owner TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('Aberto','Mitigando','Aceito','Transferido','Encerrado')),
                review_date DATE
            );
            CREATE TABLE IF NOT EXISTS incidents(
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('Baixa','Média','Alta','Crítica')),
                category TEXT NOT NULL,
                detected_at TIMESTAMP NOT NULL,
                contained_at TIMESTAMP,
                eradicated_at TIMESTAMP,
                recovered_at TIMESTAMP,
                status TEXT NOT NULL CHECK(status IN ('Aberto','Contido','Erradicado','Recuperado','Encerrado')),
                description TEXT NOT NULL,
                root_cause TEXT,
                lessons_learned TEXT,
                notification_required INTEGER NOT NULL CHECK(notification_required IN (0,1)),
                notified_at TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS dsar(
                id INTEGER PRIMARY KEY,
                requester TEXT NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('Acesso','Correção','Exclusão','Portabilidade','Oposição')),
                received_date DATE NOT NULL,
                due_date DATE NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('Aberto','Em Análise','Respondido','Encerrado','Indeferido')),
                notes TEXT
            );
            CREATE TABLE IF NOT EXISTS audits(
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                audit_date DATE NOT NULL,
                scope TEXT NOT NULL,
                findings TEXT,
                status TEXT NOT NULL CHECK(status IN ('Planejada','Em Execução','Concluída'))
            );
            CREATE TABLE IF NOT EXISTS trainings(
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                audience TEXT NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE,
                status TEXT NOT NULL CHECK(status IN ('Planejada','Em Andamento','Concluída'))
            );
            """
        )
        if not conn.execute("SELECT 1 FROM users WHERE username=?", ("admin",)).fetchone():
            conn.execute(
                "INSERT INTO users(username,password_hash,role) VALUES (?,?,?)",
                ("admin", _hash("admin123"), "admin"),
            )
        if not conn.execute("SELECT 1 FROM policies").fetchone():
            now = datetime.utcnow()
            conn.execute(
                """
                INSERT INTO policies(title,version,owner,classification,scope,status,effective_date,next_review_date,body,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "Política de Segurança da Informação",
                    "1.0",
                    "DPO/CISO",
                    "Interna",
                    "Todos os colaboradores, prestadores e sistemas do CISP",
                    "Aprovada",
                    date.today(),
                    date(date.today().year + 1, date.today().month, date.today().day),
                    template_security_policy(),
                    now,
                    now,
                ),
            )

def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def auth():
    st.sidebar.subheader("Autenticação")
    username = st.sidebar.text_input("Usuário")
    password = st.sidebar.text_input("Senha", type="password")
    login = st.sidebar.button("Entrar", use_container_width=True)
    if "user" not in st.session_state:
        st.session_state.user = None
    if login:
        with db() as conn:
            row = conn.execute("SELECT id, username, password_hash, role FROM users WHERE username=?", (username,)).fetchone()
        if row and _hash(password) == row[2]:
            st.session_state.user = {"id": row[0], "username": row[1], "role": row[3]}
        else:
            st.sidebar.error("Credenciais inválidas")
    if st.session_state.user:
        st.sidebar.success(f"Olá, {st.session_state.user['username']} ({st.session_state.user['role']})")
        if st.sidebar.button("Sair", use_container_width=True):
            st.session_state.user = None

def gated(roles):
    u = st.session_state.get("user")
    return u and (u["role"] in roles or u["role"] == "admin")

def export_xlsx(df_map: dict):
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        for name, df in df_map.items():
            df.to_excel(writer, index=False, sheet_name=name[:31] or "Sheet1")
    return output.getvalue()

def template_security_policy():
    return (
        "Objetivo: assegurar confidencialidade, integridade e disponibilidade das informações do CISP.\n"
        "Escopo: pessoas, processos e tecnologia sob responsabilidade do CISP.\n"
        "Princípios: menor privilégio, necessidade de saber, segurança por padrão.\n"
        "Controles: controle de acesso, criptografia, backup, continuidade, gestão de vulnerabilidades.\n"
        "Conformidade: aderência à ISO 27001/31000 e LGPD.\n"
        "Revisão: anual ou sob mudança significativa."
    )

def layout_header():
    st.title("CISP | Segurança, Riscos e Proteção de Dados")
    st.caption("Governança integrada de políticas, riscos, incidentes e privacidade")

def page_dashboard():
    st.subheader("Painel")
    with db() as conn:
        pol = pd.read_sql_query("SELECT status, COUNT(*) c FROM policies GROUP BY status", conn)
        rk = pd.read_sql_query("SELECT status, COUNT(*) c FROM risks GROUP BY status", conn)
        inc = pd.read_sql_query("SELECT status, COUNT(*) c FROM incidents GROUP BY status", conn)
        ds = pd.read_sql_query("SELECT status, COUNT(*) c FROM dsar GROUP BY status", conn)
    col1, col2 = st.columns(2)
    col1.metric("Políticas", int(pol.c.sum()) if not pol.empty else 0)
    col2.metric("Riscos", int(rk.c.sum()) if not rk.empty else 0)
    col3, col4 = st.columns(2)
    col3.metric("Incidentes", int(inc.c.sum()) if not inc.empty else 0)
    col4.metric("Solicitações de Titulares", int(ds.c.sum()) if not ds.empty else 0)

    st.divider()
    st.markdown("#### Matriz de Risco")
    with db() as conn:
        risks_df = pd.read_sql_query(
            "SELECT id,title,likelihood,impact,inherent,residual,status FROM risks", conn
        )
    if risks_df.empty:
        st.info("Sem riscos cadastrados")
    else:
        chart = (
            alt.Chart(risks_df)
            .mark_circle(size=200)
            .encode(
                x=alt.X("likelihood:Q", title="Probabilidade (1-5)"),
                y=alt.Y("impact:Q", title="Impacto (1-5)"),
                color=alt.Color("status:N", legend=alt.Legend(title="Status")),
                size=alt.Size("residual:Q", legend=alt.Legend(title="Risco Residual")),
                tooltip=["id", "title", "inherent", "residual", "status"],
            )
            .interactive()
        )
        st.altair_chart(chart, use_container_width=True)

def page_policies():
    st.subheader("Políticas")
    with db() as conn:
        df = pd.read_sql_query(
            "SELECT id,title,version,owner,classification,scope,status,effective_date,next_review_date,created_at,updated_at FROM policies ORDER BY updated_at DESC",
            conn,
        )
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.markdown("#### Nova/Editar Política")
    mode = st.radio("Ação", ["Criar", "Editar"], horizontal=True)
    if mode == "Criar":
        with st.form("form_policy_create", enter_to_submit=False):
            title = st.text_input("Título")
            version = st.text_input("Versão", value="1.0")
            owner = st.text_input("Responsável", value="DPO/CISO")
            classification = st.selectbox("Classificação", ["Interna", "Pública", "Restrita"])
            scope = st.text_area("Escopo", value="Todos os colaboradores, prestadores e sistemas do CISP")
            status = st.selectbox("Status", ["Rascunho", "Aprovada", "Obsoleta"])
            effective_date = st.date_input("Vigência", value=date.today())
            next_review_date = st.date_input("Próxima Revisão", value=date(date.today().year + 1, date.today().month, date.today().day))
            body = st.text_area("Conteúdo", value=template_security_policy(), height=240)
            submitted = st.form_submit_button("Salvar", use_container_width=True)
            if submitted and gated(["gestor","analista","auditor"]):
                now = datetime.utcnow()
                with db() as conn:
                    conn.execute(
                        """
                        INSERT INTO policies(title,version,owner,classification,scope,status,effective_date,next_review_date,body,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (title, version, owner, classification, scope, status, effective_date, next_review_date, body, now, now),
                    )
                st.success("Política salva")
            elif submitted:
                st.error("Sem permissão")
    else:
        with db() as conn:
            options = pd.read_sql_query("SELECT id, title || ' v' || version label FROM policies ORDER BY updated_at DESC", conn)
        if options.empty:
            st.info("Não há políticas para editar")
            return
        selected = st.selectbox("Selecione", options["label"].tolist())
        sel_id = int(options[options["label"] == selected].id.iloc[0])
        with db() as conn:
            row = conn.execute("SELECT * FROM policies WHERE id=?", (sel_id,)).fetchone()
        with st.form("form_policy_edit", enter_to_submit=False):
            title = st.text_input("Título", value=row[1])
            version = st.text_input("Versão", value=row[2])
            owner = st.text_input("Responsável", value=row[3])
            classification = st.selectbox("Classificação", ["Interna", "Pública", "Restrita"], index=["Interna","Pública","Restrita"].index(row[4]))
            scope = st.text_area("Escopo", value=row[5])
            status = st.selectbox("Status", ["Rascunho", "Aprovada", "Obsoleta"], index=["Rascunho","Aprovada","Obsoleta"].index(row[6]))
            effective_date = st.date_input("Vigência", value=pd.to_datetime(row[7]).date() if row[7] else date.today())
            next_review_date = st.date_input("Próxima Revisão", value=pd.to_datetime(row[8]).date() if row[8] else date.today())
            body = st.text_area("Conteúdo", value=row[9], height=240)
            col1, col2 = st.columns(2)
            submitted = col1.form_submit_button("Atualizar", use_container_width=True)
            deleted = col2.form_submit_button("Remover", use_container_width=True)
            if submitted and gated(["gestor","analista","auditor"]):
                with db() as conn:
                    conn.execute(
                        """
                        UPDATE policies
                        SET title=?,version=?,owner=?,classification=?,scope=?,status=?,effective_date=?,next_review_date=?,body=?,updated_at=?
                        WHERE id=?
                        """,
                        (title, version, owner, classification, scope, status, effective_date, next_review_date, body, datetime.utcnow(), sel_id),
                    )
                st.success("Política atualizada")
            elif submitted:
                st.error("Sem permissão")
            if deleted and gated(["gestor"]):
                with db() as conn:
                    conn.execute("DELETE FROM policies WHERE id=?", (sel_id,))
                st.success("Política removida")
            elif deleted:
                st.error("Sem permissão")
    st.markdown("#### Exportar")
    if st.button("Exportar tudo para Excel", use_container_width=True):
        with db() as conn:
            data = {
                "policies": pd.read_sql_query("SELECT * FROM policies", conn),
            }
        st.download_button("Baixar .xlsx", export_xlsx(data), "cisp_policies.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)

def page_assets_and_risks():
    st.subheader("Ativos e Riscos")
    tabs = st.tabs(["Ativos", "Riscos"])
    with tabs[0]:
        with db() as conn:
            assets_df = pd.read_sql_query("SELECT * FROM assets", conn)
        st.dataframe(assets_df, use_container_width=True, hide_index=True)
        with st.form("asset_form"):
            name = st.text_input("Nome do Ativo")
            atype = st.selectbox("Tipo", ["Informação", "Aplicação", "Infraestrutura", "Físico", "Pessoa"])
            owner = st.text_input("Responsável")
            criticality = st.selectbox("Criticidade", ["Baixa", "Média", "Alta", "Crítica"], index=2)
            submit = st.form_submit_button("Adicionar", use_container_width=True)
            if submit and gated(["gestor","analista"]):
                with db() as conn:
                    conn.execute("INSERT INTO assets(name,type,owner,criticality) VALUES (?,?,?,?)", (name, atype, owner, criticality))
                st.success("Ativo adicionado")
            elif submit:
                st.error("Sem permissão")
    with tabs[1]:
        with db() as conn:
            assets = pd.read_sql_query("SELECT id, name FROM assets", conn)
            risks_df = pd.read_sql_query("SELECT * FROM risks", conn)
        st.dataframe(risks_df, use_container_width=True, hide_index=True)
        with st.form("risk_form"):
            title = st.text_input("Título do Risco")
            description = st.text_area("Descrição")
            asset_label = st.selectbox("Ativo", ["Nenhum"] + assets["name"].tolist())
            asset_id = None if asset_label == "Nenhum" or assets.empty else int(assets[assets["name"] == asset_label].id.iloc[0])
            category = st.selectbox("Categoria", ["Cibernético","Operacional","Físico","Terceiros","Compliance"])
            likelihood = st.slider("Probabilidade (1-5)", 1, 5, 3)
            impact = st.slider("Impacto (1-5)", 1, 5, 3)
            inherent = likelihood * impact
            controls = st.text_area("Controles Aplicados")
            residual = st.slider("Risco Residual (1-25)", 1, 25, inherent)
            owner = st.text_input("Responsável pelo Risco")
            status = st.selectbox("Status", ["Aberto","Mitigando","Aceito","Transferido","Encerrado"])
            review_date = st.date_input("Revisão", value=date.today())
            submitted = st.form_submit_button("Registrar Risco", use_container_width=True)
            if submitted and gated(["gestor","analista"]):
                with db() as conn:
                    conn.execute(
                        """
                        INSERT INTO risks(title,description,asset_id,category,likelihood,impact,inherent,controls,residual,owner,status,review_date)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (title, description, asset_id, category, likelihood, impact, inherent, controls, residual, owner, status, review_date),
                    )
                st.success("Risco registrado")
            elif submitted:
                st.error("Sem permissão")
        st.markdown("#### Exportar")
        if st.button("Exportar Ativos e Riscos", use_container_width=True):
            with db() as conn:
                data = {
                    "assets": pd.read_sql_query("SELECT * FROM assets", conn),
                    "risks": pd.read_sql_query("SELECT * FROM risks", conn),
                }
            st.download_button("Baixar .xlsx", export_xlsx(data), "cisp_assets_risks.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)

def page_incidents():
    st.subheader("Incidentes")
    with db() as conn:
        df = pd.read_sql_query("SELECT * FROM incidents ORDER BY detected_at DESC", conn, parse_dates=["detected_at","contained_at","eradicated_at","recovered_at","notified_at"])
    st.dataframe(df, use_container_width=True, hide_index=True)
    with st.form("inc_form"):
        title = st.text_input("Título")
        severity = st.selectbox("Severidade", ["Baixa","Média","Alta","Crítica"], index=2)
        category = st.selectbox("Categoria", ["Dados Pessoais","Malware","Disponibilidade","Acesso Indevido","Outros"])
        detected_date = st.date_input("Data de detecção", value=datetime.now().date())
        detected_time = st.time_input("Hora de detecção", value=datetime.now().time())
        detected_at = datetime.combine(detected_date, detected_time)

        
        status = st.selectbox("Status", ["Aberto","Contido","Erradicado","Recuperado","Encerrado"], index=0)
        description = st.text_area("Descrição")
        root_cause = st.text_area("Causa Raiz")
        lessons = st.text_area("Lições Aprendidas")
        notification_required = st.checkbox("Requer Notificação à Autoridade/Titulares")
        notified_at = st.datetime_input("Notificado em", value=datetime.now()) if notification_required else None
        contained_at = st.datetime_input("Contido em") if status in ("Contido","Erradicado","Recuperado","Encerrado") else None
        eradicated_at = st.datetime_input("Erradicado em") if status in ("Erradicado","Recuperado","Encerrado") else None
        recovered_at = st.datetime_input("Recuperado em") if status in ("Recuperado","Encerrado") else None
        submitted = st.form_submit_button("Registrar Incidente", use_container_width=True)
        if submitted and gated(["gestor","analista","auditor"]):
            with db() as conn:
                conn.execute(
                    """
                    INSERT INTO incidents(title,severity,category,detected_at,contained_at,eradicated_at,recovered_at,status,description,root_cause,lessons_learned,notification_required,notified_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (title, severity, category, detected_at, contained_at, eradicated_at, recovered_at, status, description, root_cause, lessons, int(notification_required), notified_at),
                )
            st.success("Incidente registrado")
        elif submitted:
            st.error("Sem permissão")
    st.markdown("#### Exportar")
    if st.button("Exportar Incidentes", use_container_width=True):
        with db() as conn:
            data = {"incidents": pd.read_sql_query("SELECT * FROM incidents", conn)}
        st.download_button("Baixar .xlsx", export_xlsx(data), "cisp_incidents.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)

def page_privacy():
    st.subheader("Proteção de Dados")
    tabs = st.tabs(["Solicitações de Titulares (LGPD)", "Auditorias", "Treinamentos"])
    with tabs[0]:
        with db() as conn:
            df = pd.read_sql_query("SELECT * FROM dsar ORDER BY due_date ASC", conn, parse_dates=["received_date","due_date"])
        st.dataframe(df, use_container_width=True, hide_index=True)
        with st.form("dsar_form"):
            requester = st.text_input("Titular")
            dtype = st.selectbox("Tipo", ["Acesso","Correção","Exclusão","Portabilidade","Oposição"])
            received = st.date_input("Recebido em", value=date.today())
            due = st.date_input("Prazo", value=date.today())
            status = st.selectbox("Status", ["Aberto","Em Análise","Respondido","Encerrado","Indeferido"])
            notes = st.text_area("Observações")
            submitted = st.form_submit_button("Registrar Solicitação", use_container_width=True)
            if submitted and gated(["gestor","analista","auditor"]):
                with db() as conn:
                    conn.execute(
                        "INSERT INTO dsar(requester,type,received_date,due_date,status,notes) VALUES (?,?,?,?,?,?)",
                        (requester, dtype, received, due, status, notes),
                    )
                st.success("Solicitação registrada")
            elif submitted:
                st.error("Sem permissão")
        with db() as conn:
            kpis = pd.read_sql_query(
                """
                SELECT status, COUNT(*) c FROM dsar GROUP BY status
                """,
                conn,
            )
        st.markdown("#### KPI de Atendimentos")
        if kpis.empty:
            st.info("Sem solicitações registradas")
        else:
            chart = alt.Chart(kpis).mark_bar().encode(x="status:N", y="c:Q", color="status:N", tooltip=["status","c"])
            st.altair_chart(chart, use_container_width=True)

    with tabs[1]:
        with db() as conn:
            audits = pd.read_sql_query("SELECT * FROM audits ORDER BY audit_date DESC", conn, parse_dates=["audit_date"])
        st.dataframe(audits, use_container_width=True, hide_index=True)
        with st.form("audit_form"):
            name = st.text_input("Nome da Auditoria")
            audit_date = st.date_input("Data", value=date.today())
            scope = st.text_area("Escopo")
            findings = st.text_area("Achados")
            status = st.selectbox("Status", ["Planejada","Em Execução","Concluída"])
            submitted = st.form_submit_button("Registrar Auditoria", use_container_width=True)
            if submitted and gated(["gestor","auditor"]):
                with db() as conn:
                    conn.execute(
                        "INSERT INTO audits(name,audit_date,scope,findings,status) VALUES (?,?,?,?,?)",
                        (name, audit_date, scope, findings, status),
                    )
                st.success("Auditoria registrada")
            elif submitted:
                st.error("Sem permissão")

    with tabs[2]:
        with db() as conn:
            trainings = pd.read_sql_query("SELECT * FROM trainings ORDER BY start_date DESC", conn, parse_dates=["start_date","end_date"])
        st.dataframe(trainings, use_container_width=True, hide_index=True)
        with st.form("training_form"):
            name = st.text_input("Treinamento")
            audience = st.text_input("Público")
            start_date = st.date_input("Início", value=date.today())
            end_date = st.date_input("Término", value=date.today())
            status = st.selectbox("Status", ["Planejada","Em Andamento","Concluída"])
            submitted = st.form_submit_button("Registrar Treinamento", use_container_width=True)
            if submitted and gated(["gestor","analista","auditor"]):
                with db() as conn:
                    conn.execute(
                        "INSERT INTO trainings(name,audience,start_date,end_date,status) VALUES (?,?,?,?,?)",
                        (name, audience, start_date, end_date, status),
                    )
                st.success("Treinamento registrado")
            elif submitted:
                st.error("Sem permissão")

def page_settings():
    st.subheader("Administração")
    st.markdown("Gerenciar usuários e exportação total")
    if gated(["admin"]):
        with db() as conn:
            users = pd.read_sql_query("SELECT id, username, role FROM users", conn)
        st.dataframe(users, use_container_width=True, hide_index=True)
        with st.form("user_form"):
            username = st.text_input("Novo usuário")
            password = st.text_input("Senha", type="password")
            role = st.selectbox("Perfil", ["admin","gestor","analista","auditor"])
            submitted = st.form_submit_button("Criar Usuário", use_container_width=True)
            if submitted:
                try:
                    with db() as conn:
                        conn.execute("INSERT INTO users(username,password_hash,role) VALUES (?,?,?)", (username, _hash(password), role))
                    st.success("Usuário criado")
                except sqlite3.IntegrityError:
                    st.error("Usuário já existe")
        if st.button("Exportar Base Completa (.xlsx)", use_container_width=True):
            with db() as conn:
                data = {
                    "users": pd.read_sql_query("SELECT id, username, role FROM users", conn),
                    "policies": pd.read_sql_query("SELECT * FROM policies", conn),
                    "assets": pd.read_sql_query("SELECT * FROM assets", conn),
                    "risks": pd.read_sql_query("SELECT * FROM risks", conn),
                    "incidents": pd.read_sql_query("SELECT * FROM incidents", conn),
                    "dsar": pd.read_sql_query("SELECT * FROM dsar", conn),
                    "audits": pd.read_sql_query("SELECT * FROM audits", conn),
                    "trainings": pd.read_sql_query("SELECT * FROM trainings", conn),
                }
            st.download_button("Baixar .xlsx", export_xlsx(data), "cisp_full_export.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)
    else:
        st.error("Acesso restrito ao administrador")

def main():
    st.set_page_config(page_title="CISP Governance", page_icon="🛡️", layout="wide")
    bootstrap()
    layout_header()
    auth()
    if not st.session_state.get("user"):
        st.info("Use admin / admin123 para primeiro acesso e crie usuários próprios em Administração.")
        return
    pages = {
        "Painel": page_dashboard,
        "Políticas": page_policies,
        "Ativos e Riscos": page_assets_and_risks,
        "Incidentes": page_incidents,
        "Proteção de Dados": page_privacy,
        "Administração": page_settings,
    }
    choice = st.sidebar.radio("Navegação", list(pages.keys()))
    pages[choice]()

if __name__ == "__main__":
    main()
