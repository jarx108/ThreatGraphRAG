# ThreatGraph: Windows Setup

You need **Neo4j Desktop 2**, **Ollama**, **Python 3.13** and **Node.js 18.17+**.
Run every command in **PowerShell**, from the project folder unless a step says otherwise.

---

## 1. Neo4j Desktop 2 (graph database)

1. Download and install: https://neo4j.com/download/
2. Open Neo4j Desktop and click **Create instance**. Pick version **2026.09** (or any 5.x), then set a password and **remember it**.
3. Install GDS: open the instance's **Plugins** tab, find **Graph Data Science Library** and click **Install**. APOC is optional.
4. **Stop**, then **Start** the instance. Plugins only load on start.
5. Leave it running. The project connects to `bolt://localhost:7687` as user `neo4j`.

## 2. Ollama (local LLM)

1. Download and install: https://ollama.com/download/windows (it runs in the system tray).
2. Pull the model the project uses (about 4.9 GB):
   ```powershell
   ollama pull llama3.1:8b
   ollama list   # should show llama3.1:8b
   ```

The embedding model (`all-MiniLM-L6-v2`) downloads automatically on first run, so you don't need to pull it.

## 3. Run the project

**Prerequisites:** Python 3.13 (https://www.python.org/downloads/) and Node.js LTS (https://nodejs.org/en/download).
Open a **new** terminal after installing them.

**Install dependencies** (one time):
```powershell
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requirements.lock
cd frontend; npm ci; cd ..
```

**Create `.env`** in the project root. Replace `your-neo4j-password` with your real password:
```powershell
@"
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your-neo4j-password
NEO4J_DATABASE=neo4j
LLM_PROVIDER=ollama
LLM_MODEL=llama3.1:8b
OLLAMA_HOST=http://localhost:11434
"@ | Set-Content -Encoding utf8 .env
```

**Load the graph** (one time, about 1 minute; needs internet to download MITRE ATT&CK):
```powershell
$env:PYTHONPATH = "src"
.venv\Scripts\python -m threatgraph.graph.populate          # ATT&CK -> Neo4j
.venv\Scripts\python -m threatgraph.graph.analytics         # GDS PageRank / Louvain
.venv\Scripts\python -m threatgraph.ingestion.text_ingest   # LLM-extracted facts
```

**Start the app.** Use two terminals and keep both open.

Terminal 1, the backend API on port 8000:
```powershell
$env:PYTHONPATH = "src"
.venv\Scripts\python -m uvicorn threatgraph.api.app:app --port 8000
```
Terminal 2, the React frontend on port 5173:
```powershell
cd frontend
npm run dev
```

**Open http://localhost:5173**, go to the **GraphRAG** tab and ask a question, for example:
> Which mitigations address the ATT&CK technique Steganography (T1001.002) used by Axiom (G0001)?

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Unknown function 'gds.version'` / analytics fails | GDS isn't loaded. Install it under **Plugins**, then **Stop → Start** the instance. |
| `Cannot connect to Neo4j` / 503 in the UI | The instance isn't **Running**, or `NEO4J_PASSWORD` in `.env` is wrong. |
| `ModuleNotFoundError: threatgraph` | Run `$env:PYTHONPATH = "src"` in that terminal first. |
| `py -3.13` / `node` / `ollama` not recognized | Install it, then **open a new terminal** so PATH updates. |
| `model "llama3.1:8b" not found` | Run `ollama pull llama3.1:8b` and make sure Ollama is running in the tray. |
| UI loads but every request fails | The backend (Terminal 1) isn't running on port 8000. |
| The first answer takes 30–60 s | Normal, because Ollama is loading the model into memory. Later answers are much faster. |
| Port 8000 / 5173 already in use | Close the old terminal, or find the process with `netstat -ano \| findstr :8000` and run `Stop-Process -Id <PID>`. |
