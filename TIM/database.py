from tinydb import TinyDB, Query, where

#brute_force_table.insert({'id': 12345678, 'time': '09/02/20 12:30', 'message': '20 failed log in attempts'})
# This will create a database if it does not exist, otherwise it opens it.

class db:
    def __init__(self):
        self.db = TinyDB('db.json')
        self.brute_force_table = self.db.table('brute_force')
        self.blacklist_table = self.db.table('blacklist')
        self.multi_login_table = self.db.table('multi_login')
