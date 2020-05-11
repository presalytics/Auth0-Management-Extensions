from auth0_mgr.misc.keycloak import UserImporter

importer = UserImporter("keycloakdb.json")

importer.to_file()