from app import app, db  # Adjust the import according to your actual module names
   
with app.app_context():
    db.create_all()
    print("Database tables created.")