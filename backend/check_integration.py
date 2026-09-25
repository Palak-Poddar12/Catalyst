"""Quick static/import check for the merged forensic pipeline."""
from app.forensics.member1_adapter import normalize_member1_result
from member1_forensic_analyzer import analyze_eml_file

print("Member 1 analyzer import: OK")
print("Member 1 adapter import: OK")
print("Analyzer:", analyze_eml_file.__name__)
