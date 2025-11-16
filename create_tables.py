# create_tables.py
from app import app, db
# import the models to ensure SQLAlchemy knows them
from app import Branch, Truck, User, Customer, Consignment, ConsignmentTruck, TruckAssignment
import bcrypt

with app.app_context():
    print("Creating all tables (if not present)...")
    db.create_all()
    print("Tables created (or already present).")

    # seed minimal branches & trucks & a user only if none exist (safe)
    if not Branch.query.first():
        print("Seeding sample branches & trucks...")
        branches = ['Capital', 'CityA', 'CityB']
        for loc in branches:
            b = Branch(location=loc)
            db.session.add(b)
            db.session.commit()
            # add one truck per branch for testing
            db.session.add(Truck(location=loc, branch_id=b.id))
        db.session.commit()
        print("Seeded branches & trucks.")

    if not User.query.first():
        print("Seeding a test manager user...")
        hashed = bcrypt.hashpw('managerpass'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.session.add(User(username='manager1', password=hashed, role='Manager'))
        db.session.commit()
        print("Seeded users.")
    print("Done.")
