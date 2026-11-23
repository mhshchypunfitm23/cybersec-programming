#!/usr/bin/env python3
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Classification

tm = TM("University Student Portal Threat Model (Hardened)")
tm.description = "Захищена модель загроз вебпорталу особистого кабінету студента"
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
web_portal.implementsAuthenticationScheme = True
web_portal.sanitizesInput = True
web_portal.encodesOutput = True

auth_service = Server("Auth Service")
auth_service.inBoundary = internal_net
auth_service.OS = "Linux"
auth_service.isHardened = True
auth_service.implementsAuthenticationScheme = True
auth_service.sanitizesInput = True

grades_api = Server("Grades API")
grades_api.inBoundary = internal_net
grades_api.OS = "Linux"
grades_api.isHardened = True
grades_api.implementsAuthenticationScheme = True
grades_api.sanitizesInput = True
grades_api.encodesOutput = True

db = Datastore("Student Database")
db.inBoundary = internal_net
db.OS = "Linux"
db.isSQL = True
db.inScope = True
db.isEncrypted = True
db.isHardened = True
db.maxClassification = Classification.RESTRICTED

login_req = Dataflow(student, web_portal, "HTTPS Login Request")
login_req.protocol = "HTTPS"
login_req.dstPort = 443
login_req.data = "Credentials"
login_req.isEncrypted = True

auth_check = Dataflow(web_portal, auth_service, "mTLS Verify Credentials")
auth_check.protocol = "HTTPS"
auth_check.dstPort = 8443
auth_check.isEncrypted = True

token_res = Dataflow(auth_service, web_portal, "mTLS Return JWT Token")
token_res.protocol = "HTTPS"
token_res.dstPort = 8443
token_res.isEncrypted = True

grades_req = Dataflow(web_portal, grades_api, "mTLS Request Student Grades")
grades_req.protocol = "HTTPS"
grades_req.dstPort = 8443
grades_req.isEncrypted = True

db_query = Dataflow(grades_api, db, "TLS SQL Query for Grades")
db_query.protocol = "TLS"
db_query.dstPort = 5432
db_query.isEncrypted = True

if __name__ == "__main__":
    tm.process()
