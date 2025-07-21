import sqlite3
from typing import List, Optional
from src.detector import Incident


class Database:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self._create_table()

    def _create_table(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                category TEXT,
                severity TEXT,
                message TEXT       
            )
        """)

        self.conn.commit()

    def _insert_incidents(self, incidents: List[Incident]):
        cursor = self.conn.cursor()
        for inc in incidents:
            cursor.execute(
                "INSERT INTO incidents (timestamp, category, severity, message) VALUES (?,?,?,?)",
                (inc.timestamp, inc.category, inc.severity, inc.message)
            )
        self.conn.commit()

    def list_incidents(self, severity: Optional[str] = None) -> List[Incident]:
        cursor = self.conn.cursor()
        if severity:
            cursor.execute("SELECT timestamp, category, severity, message FROM incidents WHERE severity=?", (severity,))
        else:
            cursor.execute("SELECT timestamp, category, severity, message FROM incidents")

        rows = cursor.fetchall()
        return [Incident(*row) for row in rows]
    
    def generate_report(self, fmt: str = "text") -> str:
        cursor = self.conn.cursor()
        cursor.execute("SELECT category, COUNT(*) FROM Incidents GROUP BY category")
        rows = cursor.fetchall()

        if fmt == "json":
            import json
            return json.dumps({category: count for category, count in rows}, indent = 2)

        elif fmt == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["category", "count"])
            writer.writerows(rows)
            return output.getvalue()
        
        elif fmt == "html":
            html = "<html><body><h2>Incident Report</h2><table border='1'><tr><th>Category</th><th>Count</th></tr>"
            for category, count in rows:
                html += f"<tr><td>{category}</td><td>{count}</td></tr>"
            
            html += "</table></body></html>"
            return html
        
        else:   # default to text
            return "\n".join([f"{category}: {count}" for category, count in rows])
        

    def close(self):
        self.conn.close()