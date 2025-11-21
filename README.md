# 🛡️ Sistema CISP – Gestão de Segurança, Riscos e Proteção de Dados  
Aplicação completa desenvolvida em **Python + Streamlit** para apoiar o CISP (Conselho de Segurança Pública) no gerenciamento centralizado de:

- Políticas de Segurança da Informação  
- Gestão de Ativos e Riscos  
- Incidentes de Segurança  
- Proteção de Dados (LGPD/GDPR)  
- Auditorias  
- Treinamentos  
- Deteção Automática de Riscos (simulação)  
- Controlo de Utilizadores e Perfis  

A aplicação inclui interface moderna, dashboard interativo, permissões por perfil e integração com **PostgreSQL + SQLAlchemy**.

---

## 🚀 Funcionalidades Principais

### 🔐 **1. Autenticação e Perfis de Acesso**
- Página de login dedicada  
- Perfis: **Admin**, **Gestor**, **Analista**, **Auditor**  
- Permissões automáticas:
  - Analista → não vê políticas  
  - Auditor → apenas auditorias e incidentes  
  - Gestor → tudo menos admin  
  - Admin → acesso total  

---

### 🗂️ **2. Gestão de Políticas**
- Cadastro, edição e versionamento  
- Classificação da política  
- Datas de vigência e revisão  
- Exportação para Excel  

---

### 🧩 **3. Ativos e Riscos**
- Inventário de ativos  
- Matriz de risco automática  
- Risco inerente, controles e risco residual  
- Exportação de relatórios  

---

### 🚨 **4. Incidentes de Segurança**
- Registo completo: deteção → contenção → erradicação → encerramento  
- Severidade, impacto e análises  
- Upload de evidências  
- Indicadores gráficos  

---

### 📜 **5. Conformidade e Privacidade (LGPD)**
- DSAR (Solicitações de titulares)  
- Auditorias internas  
- Treinamentos de conscientização  

---

### 🤖 **6. Módulo de Deteção Automática (Simulado)**
Inclui:
- Gerador de logs fictícios  
- Engine de correlação de eventos  
- Identificação automática de riscos  
- Dashboard com gráficos reais  

Simula a integração com SIEM, firewalls, antivírus, UEBA e CVE.

---

### 👥 **7. Administração**
- Gestão completa de utilizadores  
- Logs de auditoria do sistema  
- Exportação global da base de dados  

---

## 🗄️ Arquitetura Técnica

- **Frontend:** Streamlit  
- **Backend:** Python  
- **ORM:** SQLAlchemy  
- **Banco de Dados:** PostgreSQL  
- **Autenticação:** bcrypt hashing  
- **Gráficos:** Matplotlib  
- **Deploy:** Streamlit Cloud  

---

## 📦 Instalação Local

### 1. Clonar este repositório

```bash
git clone https://github.com/SEU_USUARIO/cisp-streamlit.git
cd cisp-streamlit
