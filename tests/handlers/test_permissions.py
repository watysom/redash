from redash.models import AccessPermission
from redash.permissions import ACCESS_TYPE_MODIFY
from tests import BaseTestCase


class TestObjectPermissionsListGet(BaseTestCase):
    def test_returns_empty_list_when_no_permissions(self):
        query = self.factory.create_query()
        user = self.factory.user
        rv = self.make_request("get", "/api/queries/{}/acl".format(query.id), user=user)

        self.assertEqual(rv.status_code, 200)
        self.assertEqual({}, rv.json)

    def test_returns_permissions_user(self):
        query = self.factory.create_query()
        user = self.factory.user

        AccessPermission.grant(
            obj=query,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=self.factory.user,
        )

        rv = self.make_request("get", "/api/queries/{}/acl".format(query.id), user=user)

        self.assertEqual(rv.status_code, 200)
        self.assertIn("modify", rv.json)
        self.assertEqual(user.id, rv.json["modify"][0]["id"])

    def rest_returns_permission_group(self):
        query = self.factory.create_query()
        user = self.factory.user
        group = user.groups[0]

        AccessPermission.grant(obj=query, access_type=ACCESS_TYPE_MODIFY, grantor=user, grantee=group)

        rv = self.make_request("get", "/api/queries/{}/acl".format(query.id), user=user)

        self.assertEqual(rv.status_code, 200)
        self.assertIn("modify", rv.json)
        self.assertEqual(group.id, rv.json["modify"][0]["id"])

    def test_returns_404_for_outside_of_organization_users(self):
        query = self.factory.create_query()
        user = self.factory.create_user(org=self.factory.create_org())
        rv = self.make_request("get", "/api/queries/{}/acl".format(query.id), user=user)

        self.assertEqual(rv.status_code, 404)


class TestObjectPermissionsListPost(BaseTestCase):
    def test_creates_permission_if_the_user_is_an_owner(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user()

        data = {
            "access_type": ACCESS_TYPE_MODIFY,
            "grantee_type": other_user.__tablename__,
            "grantee_id": other_user.id,
        }

        rv = self.make_request("post", "/api/queries/{}/acl".format(query.id), user=query.user, data=data)

        self.assertEqual(200, rv.status_code)
        self.assertTrue(AccessPermission.exists(query, ACCESS_TYPE_MODIFY, other_user))

    def test_returns_403_if_the_user_isnt_owner(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user()

        data = {
            "access_type": ACCESS_TYPE_MODIFY,
            "grantee_type": other_user.__tablename__,
            "grantee_id": other_user.id,
        }

        rv = self.make_request("post", "/api/queries/{}/acl".format(query.id), user=other_user, data=data)
        self.assertEqual(403, rv.status_code)

    def test_returns_400_if_the_grantee_user_isnt_from_organization(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user(org=self.factory.create_org())

        data = {
            "access_type": ACCESS_TYPE_MODIFY,
            "grantee_type": other_user.__tablename__,
            "grantee_id": other_user.id,
        }

        rv = self.make_request("post", "/api/queries/{}/acl".format(query.id), user=query.user, data=data)
        self.assertEqual(400, rv.status_code)

    def test_returns_400_if_the_grantee_group_isnt_from_organization(self):
        query = self.factory.create_query()
        other_group = self.factory.create_group(org=self.factory.create_org())

        data = {
            "access_type": ACCESS_TYPE_MODIFY,
            "grantee_type": other_group.__tablename__,
            "grantee_id": other_group.id,
        }

        rv = self.make_request("post", "/api/queries/{}/acl".format(query.id), user=query.user, data=data)
        self.assertEqual(400, rv.status_code)

    def test_returns_404_if_the_user_from_different_org(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user(org=self.factory.create_org())

        data = {
            "access_type": ACCESS_TYPE_MODIFY,
            "grantee_type": other_user.__tablename__,
            "grantee_id": other_user.id,
        }

        rv = self.make_request("post", "/api/queries/{}/acl".format(query.id), user=other_user, data=data)
        self.assertEqual(404, rv.status_code)

    def test_accepts_only_correct_access_types(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user()

        data = {"access_type": "random string", "grantee_type": other_user.__tablename__, "grantee_id": other_user.id}

        rv = self.make_request("post", "/api/queries/{}/acl".format(query.id), user=query.user, data=data)

        self.assertEqual(400, rv.status_code)


class TestObjectPermissionsListDelete(BaseTestCase):
    def test_removes_permission(self):
        query = self.factory.create_query()
        user = self.factory.user
        other_user = self.factory.create_user()

        data = {
            "access_type": ACCESS_TYPE_MODIFY,
            "grantee_type": other_user.__tablename__,
            "grantee_id": other_user.id,
        }

        AccessPermission.grant(
            obj=query,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=other_user,
        )

        rv = self.make_request("delete", "/api/queries/{}/acl".format(query.id), user=user, data=data)

        self.assertEqual(rv.status_code, 200)

        self.assertFalse(AccessPermission.exists(query, ACCESS_TYPE_MODIFY, other_user))

    def test_removes_permission_created_by_another_user(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user()

        data = {
            "access_type": ACCESS_TYPE_MODIFY,
            "grantee_type": other_user.__tablename__,
            "grantee_id": other_user.id,
        }

        AccessPermission.grant(
            obj=query,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=other_user,
        )

        rv = self.make_request(
            "delete",
            "/api/queries/{}/acl".format(query.id),
            user=self.factory.create_admin(),
            data=data,
        )

        self.assertEqual(rv.status_code, 200)

        self.assertFalse(AccessPermission.exists(query, ACCESS_TYPE_MODIFY, other_user))

    def test_returns_404_for_outside_of_organization_users(self):
        query = self.factory.create_query()
        user = self.factory.create_user(org=self.factory.create_org())
        data = {"access_type": ACCESS_TYPE_MODIFY, "grantee_type": user.__tablename__, "grantee_id": user.id}
        rv = self.make_request("delete", "/api/queries/{}/acl".format(query.id), user=user, data=data)

        self.assertEqual(rv.status_code, 404)

    def test_returns_403_for_non_owner(self):
        query = self.factory.create_query()
        user = self.factory.create_user()

        data = {"access_type": ACCESS_TYPE_MODIFY, "grantee_type": user.__tablename__, "grantee_id": user.id}
        rv = self.make_request("delete", "/api/queries/{}/acl".format(query.id), user=user, data=data)

        self.assertEqual(rv.status_code, 403)

    def test_returns_200_even_if_there_is_no_permission(self):
        query = self.factory.create_query()
        user = self.factory.create_user()

        data = {"access_type": ACCESS_TYPE_MODIFY, "grantee_type": user.__tablename__, "grantee_id": user.id}

        rv = self.make_request("delete", "/api/queries/{}/acl".format(query.id), user=query.user, data=data)

        self.assertEqual(rv.status_code, 200)


class TestCheckPermissionsGet(BaseTestCase):
    def test_returns_true_for_existing_permission(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user()

        AccessPermission.grant(
            obj=query,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=other_user,
        )

        rv = self.make_request(
            "get",
            "/api/queries/{}/acl/{}".format(query.id, ACCESS_TYPE_MODIFY),
            user=other_user,
        )

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(True, rv.json["response"])

    def test_returns_true_for_existing_permission_groups(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user()
        group1 = self.factory.create_group(name="Group1")
        group2 = self.factory.create_group(name="Group2")
        other_user.update_group_assignments([group1.name, group2.name])

        AccessPermission.grant(
            obj=query,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=[group for group in other_user.groups if group.name == "Group1"][0],
        )

        rv = self.make_request("get", "/api/queries/{}/acl/{}".format(query.id, ACCESS_TYPE_MODIFY), user=other_user)

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(True, rv.json["response"])

    def test_returns_false_for_existing_permission(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user()

        rv = self.make_request(
            "get",
            "/api/queries/{}/acl/{}".format(query.id, ACCESS_TYPE_MODIFY),
            user=other_user,
        )

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(False, rv.json["response"])

    def test_returns_404_for_outside_of_org_users(self):
        query = self.factory.create_query()
        other_user = self.factory.create_user(org=self.factory.create_org())

        rv = self.make_request(
            "get",
            "/api/queries/{}/acl/{}".format(query.id, ACCESS_TYPE_MODIFY),
            user=other_user,
        )

        self.assertEqual(rv.status_code, 404)
