#!/usr/bin/env python3
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Classification

tm = TM("University Student Portal Threat Model")
tm.description = "Модель загроз для вебпорталу особистого кабінету студента"
tm.isOrdered = True

internet = Boundary("Internet")
dmz = Boundary("DMZ")
internal_net = Boundary("Internal University Network")

student = Actor("Student")
student.inBoundary = internet

web_portal = Server("Web Portal Frontend")
web_portal.inBoundary = dmz
web_portal.OS = "Linux"
web_portal.isHardened = True

auth_service = Server("Auth Service")
auth_service.inBoundary = internal_net
auth_service.OS = "Linux"
auth_service.implementsAuthenticationScheme = True

grades_api = Server("Grades API")
grades_api.inBoundary = internal_net
grades_api.OS = "Linux"
grades_api.sanitizesInput = False

db = Datastore("Student Database")
db.inBoundary = internal_net
db.OS = "Linux"
db.isSQL = True
db.inScope = True
db.isEncrypted = False
db.maxClassification = Classification.RESTRICTED

login_req = Dataflow(student, web_portal, "HTTPS Login Request")
login_req.protocol = "HTTPS"
login_req.dstPort = 443
login_req.data = "Credentials"

auth_check = Dataflow(web_portal, auth_service, "Verify Credentials")
auth_check.protocol = "HTTP"
auth_check.dstPort = 8080

token_res = Dataflow(auth_service, web_portal, "Return JWT Token")
token_res.protocol = "HTTP"
token_res.dstPort = 8080

grades_req = Dataflow(web_portal, grades_api, "Request Student Grades")
grades_req.protocol = "HTTP"
grades_req.dstPort = 8000

db_query = Dataflow(grades_api, db, "SQL Query for Grades")
db_query.protocol = "TCP"
db_query.dstPort = 5432

if __name__ == "__main__":
    tm.process()
