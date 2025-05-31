from allianceauth.utils.testing import NoSocketsTestCase

from ..helpers import RolesSet
from .factories import create_matched_role, create_role


class TestRolesSet(NoSocketsTestCase):
    def test_can_create_simple(self):
        # given
        roles_raw = [create_role()]
        # when
        roles = RolesSet(roles_raw)
        # then
        self.assertListEqual(list(roles), roles_raw)

    def test_can_create_empty(self):
        # when
        roles = RolesSet([])
        # then
        self.assertListEqual(list(roles), [])

    def test_raises_exception_if_roles_raw_of_wrong_type(self):
        with self.assertRaises(TypeError):
            RolesSet({"id": 1})

    def test_raises_exception_if_list_contains_non_dict(self):
        # given
        roles_raw = [create_role(), "not_valid"]
        # when/then
        with self.assertRaises(TypeError):
            RolesSet(roles_raw)

    def test_roles_are_equal(self):
        # given
        role_a = create_role()
        role_b = create_role()
        roles_a = RolesSet([role_a, role_b])
        roles_b = RolesSet([role_a, role_b])
        # when/then
        self.assertEqual(roles_a, roles_b)

    def test_roles_are_not_equal(self):
        # given
        role_a = create_role()
        role_b = create_role()
        roles_a = RolesSet([role_a, role_b])
        roles_b = RolesSet([role_a])
        # when/then
        self.assertNotEqual(roles_a, roles_b)

    def test_different_objects_are_not_equal(self):
        roles_a = RolesSet([])
        self.assertFalse(roles_a == "invalid")

    def test_len(self):
        # given
        role_a = create_role()
        role_b = create_role()
        roles = RolesSet([role_a, role_b])
        # when/then
        self.assertEqual(len(roles), 2)

    def test_contains(self):
        # given
        role_a = create_role(id=1)
        roles = RolesSet([role_a])
        # when/then
        self.assertTrue(1 in roles)
        self.assertFalse(99 in roles)

    def test_objects_are_hashable(self):
        # given
        role_a = create_role()
        role_b = create_role()
        role_c = create_role()
        roles_a = RolesSet([role_a, role_b])
        roles_b = RolesSet([role_b, role_a])
        roles_c = RolesSet([role_a, role_b, role_c])
        # when/then
        self.assertIsNotNone(hash(roles_a))
        self.assertEqual(hash(roles_a), hash(roles_b))
        self.assertNotEqual(hash(roles_a), hash(roles_c))

    def test_create_from_matched_roles(self):
        role_a = create_role()
        role_b = create_role()
        matched_roles = [
            create_matched_role(role_a, True),
            create_matched_role(role_b, False),
        ]
        # when
        roles = RolesSet.create_from_matched_roles(matched_roles)
        # then
        self.assertEqual(roles, RolesSet([role_a, role_b]))

    def test_return_role_ids_default(self):
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        roles = RolesSet([role_a, role_b])
        # when/then
        self.assertSetEqual(roles.ids(), {1, 2})

    def test_return_role_ids_empty(self):
        # given
        roles = RolesSet([])
        # when/then
        self.assertSetEqual(roles.ids(), set())


class TestRolesSetSubset(NoSocketsTestCase):
    def test_ids_only(self):
        # given
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        role_c = create_role(id=3)
        roles_all = RolesSet([role_a, role_b, role_c])
        # when
        roles_subset = roles_all.subset({1, 3})
        # then
        self.assertEqual(roles_subset, RolesSet([role_a, role_c]))

    def test_ids_as_string_work_too(self):
        # given
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        role_c = create_role(id=3)
        roles_all = RolesSet([role_a, role_b, role_c])
        # when
        roles_subset = roles_all.subset({"1", "3"})
        # then
        self.assertEqual(roles_subset, RolesSet([role_a, role_c]))

    def test_managed_only(self):
        # given
        role_a = create_role(id=1)
        role_m = create_role(id=13, managed=True)
        roles_all = RolesSet([role_a, role_m])
        # when
        roles_subset = roles_all.subset(managed_only=True)
        # then
        self.assertEqual(roles_subset, RolesSet([role_m]))

    def test_ids_and_managed_only(self):
        # given
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        role_m = create_role(id=13, managed=True)
        roles_all = RolesSet([role_a, role_b, role_m])
        # when
        roles_subset = roles_all.subset({1, 13}, managed_only=True)
        # then
        self.assertEqual(roles_subset, RolesSet([role_m]))

    def test_ids_are_empty(self):
        # given
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        roles_all = RolesSet([role_a, role_b])
        roles_subset = roles_all.subset([])
        # then
        self.assertEqual(roles_subset, RolesSet([]))

    def test_no_parameters(self):
        # given
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        roles_all = RolesSet([role_a, role_b])
        roles_subset = roles_all.subset()
        # then
        self.assertEqual(roles_subset, roles_all)

    def test_should_return_role_names_only(self):
        # given
        role_a = create_role(name="alpha")
        role_b = create_role(name="bravo")
        role_c1 = create_role(name="charlie")
        role_c2 = create_role(name="Charlie")
        roles_all = RolesSet([role_a, role_b, role_c1, role_c2])
        # when
        roles_subset = roles_all.subset(role_names={"bravo", "charlie"})
        # then
        self.assertSetEqual(roles_subset, RolesSet([role_b, role_c1, role_c2]))


class TestRolesSetHasRoles(NoSocketsTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        role_c = create_role(id=3)
        cls.all_roles = RolesSet([role_a, role_b, role_c])

    def test_true_if_all_roles_exit(self):
        self.assertTrue(self.all_roles.has_roles([1, 2]))

    def test_true_if_all_roles_exit_str(self):
        self.assertTrue(self.all_roles.has_roles(["1", "2"]))

    def test_false_if_role_does_not_exit(self):
        self.assertFalse(self.all_roles.has_roles([99]))

    def test_false_if_one_role_does_not_exit(self):
        self.assertFalse(self.all_roles.has_roles([1, 99]))

    def test_true_for_empty_roles(self):
        self.assertTrue(self.all_roles.has_roles([]))


class TestRolesSetGetMatchingRolesByName(NoSocketsTestCase):
    def test_return_role_if_matches(self):
        # given
        role_a = create_role(name="alpha")
        role_b = create_role(name="bravo")
        roles = RolesSet([role_a, role_b])
        # when
        result = roles.role_by_name("alpha")
        # then
        self.assertEqual(result, role_a)

    def test_return_role_if_matches_and_limit_max_length(self):
        # given
        role_name = "x" * 120
        role = create_role(name="x" * 100)
        roles = RolesSet([role])
        # when
        result = roles.role_by_name(role_name)
        # then
        self.assertEqual(result, role)

    def test_return_empty_if_not_matches(self):
        # given
        role_a = create_role(name="alpha")
        role_b = create_role(name="bravo")
        roles = RolesSet([role_a, role_b])
        # when
        result = roles.role_by_name("unknown")
        # then
        self.assertIsNone(result)


class TestRolesSetUnion(NoSocketsTestCase):
    def test_distinct_sets(self):
        # given
        role_a = create_role()
        role_b = create_role()
        roles_1 = RolesSet([role_a])
        roles_2 = RolesSet([role_b])
        # when
        result = roles_1.union(roles_2)
        # then
        self.assertEqual(result, RolesSet([role_a, role_b]))

    def test_overlapping_sets(self):
        # given
        role_a = create_role()
        role_b = create_role()
        role_c = create_role()
        roles_1 = RolesSet([role_a, role_b])
        roles_2 = RolesSet([role_b, role_c])
        # when
        result = roles_1.union(roles_2)
        self.assertEqual(result, RolesSet([role_a, role_b, role_c]))

    def test_identical_sets(self):
        role_a = create_role()
        role_b = create_role()
        roles_1 = RolesSet([role_a, role_b])
        roles_2 = RolesSet([role_a, role_b])
        # when
        result = roles_1.union(roles_2)
        self.assertEqual(result, RolesSet([role_a, role_b]))


class TestRolesSetDifference(NoSocketsTestCase):
    def test_distinct_sets(self):
        # given
        role_a = create_role()
        role_b = create_role()
        role_c = create_role()
        role_d = create_role()
        roles_1 = RolesSet([role_a, role_b])
        roles_2 = RolesSet([role_c, role_d])
        # when
        result = roles_1.difference(roles_2)
        # then
        self.assertEqual(result, RolesSet([role_a, role_b]))

    def test_overlapping_sets(self):
        # given
        role_a = create_role()
        role_b = create_role()
        role_c = create_role()
        roles_1 = RolesSet([role_a, role_b])
        roles_2 = RolesSet([role_b, role_c])
        # when
        result = roles_1.difference(roles_2)
        # then
        self.assertEqual(result, RolesSet([role_a]))

    def test_identical_sets(self):
        # given
        role_a = create_role()
        role_b = create_role()
        roles_1 = RolesSet([role_a, role_b])
        roles_2 = RolesSet([role_a, role_b])
        # when
        result = roles_1.difference(roles_2)
        # then
        self.assertEqual(result, RolesSet([]))
