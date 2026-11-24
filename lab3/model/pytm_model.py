#!/usr/bin/env python3
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Classification

tm = TM("Lab 3 - University Portal Demo Stand (Nginx + FastAPI + PostgreSQL)")
tm.description = "Модель загроз демонстраційного стенду вебпорталу університету за методологією STRIDE"
tm.isOrdered = True

internet = Boundary("Internet")
dmz = Boundary("DMZ (Nginx Edge)")
internal = Boundary("Internal Network (Docker Bridge)")

client = Actor("Student / Client Browser")
client.inBoundary = internet

nginx = Server("Nginx Reverse Proxy (8080)")
nginx.inBoundary = dmz
nginx.OS = "Alpine Linux"
nginx.isHardened = True
nginx.sanitizesInput = False

api = Server("FastAPI Backend (8000)")
api.inBoundary = internal
api.OS = "Debian Slim"
api.implementsAuthenticationScheme = True
api.sanitizesInput = False
api.encodesOutput = False

db = Datastore("PostgreSQL 15 Database (5432)")
db.inBoundary = internal
db.OS = "Linux"
db.isSQL = True
db.inScope = True
db.isEncrypted = False
db.maxClassification = Classification.RESTRICTED

req_ext = Dataflow(client, nginx, "HTTP/HTTPS Request (:8080)")
req_ext.protocol = "HTTP"
req_ext.dstPort = 8080
req_ext.data = "User Credentials & Search Query"

req_int = Dataflow(nginx, api, "Proxy Pass to FastAPI (:8000)")
req_int.protocol = "HTTP"
req_int.dstPort = 8000
req_int.data = "API Payload"

res_int = Dataflow(api, nginx, "JSON Response")
res_int.protocol = "HTTP"
res_int.dstPort = 8000

db_query = Dataflow(api, db, "SQL Query (:5432)")
db_query.protocol = "TCP"
db_query.dstPort = 5432
db_query.data = "Student Grades & Accounts"

if __name__ == "__main__":
    tm.process()
