"""Owned synthetic input fixtures. No accounts, writes, external traffic or solution API."""
import html
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        bad = parsed.path.startswith('/bad/')
        kind = parsed.path.rsplit('/', 1)[-1]
        value = parse_qs(parsed.query).get('q', [''])[0][:400]
        if kind == 'sql':
            with sqlite3.connect(':memory:') as db:
                db.execute('CREATE TABLE products (name TEXT)')
                db.execute("INSERT INTO products VALUES ('apple')")
                try:
                    row = db.execute("SELECT count(*) FROM products WHERE name = '"+value+"'") if bad else db.execute('SELECT count(*) FROM products WHERE name = ?', (value,))
                    content = 'Matches: ' + str(row.fetchone()[0])
                except sqlite3.Error:
                    content = 'Invalid search'
        else:
            content = value if bad else html.escape(value)
        data = ('<!doctype html><html><body><h1>Search preview</h1><div>'+content+'</div></body></html>').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
