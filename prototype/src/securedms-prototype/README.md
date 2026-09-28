# SecureDMS – SIH Prototype

Case-centric secure document management: JWT auth, role + case-level access, SHA-256 integrity,
document versioning, hash-chained audit trail, search and an AI-labelled summary.

## Run
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```
Open http://127.0.0.1:8000 (API docs: /docs). Sample files are in `sample_docs/`.

Demo users (password `demo123`): officer@police.gov, forensic@lab.gov, legal@legal.gov, auditor@audit.gov, admin@it.gov

## Demo flow
1. Login as Police officer → create `CASE-2026-00124` (assign Police, Forensics, Legal, Audit).
2. Upload `FIR_2026_00124.txt` (type FIR). Re-upload same filename → v2 appears in Versions.
3. Login as Forensics → upload `Forensic_Report.txt` (only Forensic/Evidence types allowed).
4. Update a file: click "Update file (new version)" on any document; the old version stays in Versions.
5. Login as Admin -> sees every case (oversight role), can update/verify/audit.
6. Login as Legal → can view the case, can only upload Legal Notice / Court Filing.
7. Verify a document → VALID. As Police click "Simulate tamper (demo)" → Verify again → INTEGRITY FAILURE.
8. Audit trail shows every action; the hash chain confirms the log is untampered.
9. Search "suspicious transactions" and generate the case summary.

## Prototype vs PRD
SQLite + local disk stand in for PostgreSQL + MinIO. Search is keyword-ranked and the summary is
extractive (no LLM); `search()` and `summary()` in `main.py` are the plug-in points for pgvector embeddings and an LLM.
