from tinydb import TinyDB, Query

def create_database():
    db = TinyDB('db.json')
    
    # Create tables
    brute_force_table = db.table('brute_force')

    # Insert a row
    brute_force_table.insert({'id': 12345678, 'time': '09/02/20 12:30', 'message': '20 failed log in attempts'})

create_database()