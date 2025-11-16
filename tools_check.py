# tools_check.py
from app import app, db, Branch, Truck, User, Consignment

with app.app_context():
    print("---- Branches ----")
    for b in Branch.query.all():
        print(b.id, b.location)
    print("\n---- Trucks ----")
    for t in Truck.query.all():
        print(t.id, t.location, "branch:", t.branch_id)
    print("\n---- Users (employees/drivers) ----")
    for u in User.query.all():
        print(u.id, u.username, u.role, "branch:", u.branch_id)
    print("\n---- Consignments ----")
    for c in Consignment.query.all():
        print(c.id, "vol:", c.volume, "dest:", c.destination, "branch:", c.branch_id, "status:", c.status)
