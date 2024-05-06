from redash.models import AccessPermission
from redash.permissions import ACCESS_TYPE_MODIFY, ACCESS_TYPE_VIEW
from tests import BaseTestCase


class TestAccessPermissionGrant(BaseTestCase):
    def test_creates_correct_object_user(self):
        q = self.factory.create_query()
        permission = AccessPermission.grant(
            obj=q,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=self.factory.user,
        )

        self.assertEqual(permission.object, q)
        self.assertEqual(permission.grantor, self.factory.user)
        self.assertEqual(permission.grantee, self.factory.user)
        self.assertEqual(permission.access_type, ACCESS_TYPE_MODIFY)

    def test_create_correct_object_group(self):
        q = self.factory.create_query()
        user = self.factory.user
        group = user.groups[0]
        permission = AccessPermission.grant(
            obj=q, access_type=ACCESS_TYPE_MODIFY, grantor=self.factory.user, grantee=group
        )

        self.assertEqual(permission.object, q)
        self.assertEqual(permission.grantor, user)
        self.assertEqual(permission.grantee, group)
        self.assertEqual(permission.access_type, ACCESS_TYPE_MODIFY)

    def test_returns_existing_object_if_exists(self):
        q = self.factory.create_query()
        permission1 = AccessPermission.grant(
            obj=q,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=self.factory.user,
        )

        permission2 = AccessPermission.grant(
            obj=q,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=self.factory.user,
        )

        self.assertEqual(permission1.id, permission2.id)


class TestAccessPermissionRevoke(BaseTestCase):
    def test_deletes_nothing_when_no_permission_exists(self):
        q = self.factory.create_query()
        self.assertEqual(0, AccessPermission.revoke(q, self.factory.user, ACCESS_TYPE_MODIFY))

    def test_deletes_permission_user(self):
        q = self.factory.create_query()
        AccessPermission.grant(
            obj=q,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=self.factory.user,
        )
        self.assertEqual(1, AccessPermission.revoke(q, self.factory.user, ACCESS_TYPE_MODIFY))

    def test_deletes_permission_group(self):
        q = self.factory.create_query()
        group = self.factory.user.groups[0]
        AccessPermission.grant(obj=q, access_type=ACCESS_TYPE_MODIFY, grantor=self.factory.user, grantee=group)
        self.assertEqual(1, AccessPermission.revoke(q, group, ACCESS_TYPE_MODIFY))

    def test_deletes_permission_for_only_given_grantee_on_given_grant_type(self):
        q = self.factory.create_query()
        first_user = self.factory.create_user()
        second_user = self.factory.create_user()

        AccessPermission.grant(
            obj=q,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=first_user,
        )

        AccessPermission.grant(
            obj=q,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=second_user,
        )

        AccessPermission.grant(
            obj=q,
            access_type=ACCESS_TYPE_VIEW,
            grantor=self.factory.user,
            grantee=second_user,
        )

        self.assertEqual(1, AccessPermission.revoke(q, second_user, ACCESS_TYPE_VIEW))

    def test_deletes_all_permissions_if_no_type_given(self):
        q = self.factory.create_query()

        AccessPermission.grant(
            obj=q,
            access_type=ACCESS_TYPE_MODIFY,
            grantor=self.factory.user,
            grantee=self.factory.user,
        )

        AccessPermission.grant(
            obj=q,
            access_type=ACCESS_TYPE_VIEW,
            grantor=self.factory.user,
            grantee=self.factory.user,
        )

        self.assertEqual(2, AccessPermission.revoke(q, self.factory.user))


class TestAccessPermissionFind(BaseTestCase):
    pass


class TestAccessPermissionExists(BaseTestCase):
    pass
