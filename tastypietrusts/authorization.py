from __future__ import unicode_literals

import settings

from tastypie.exceptions import TastypieError, Unauthorized
from tastypie.compat import get_module_name
from tastypie.authorization import Authorization, DjangoAuthorization

class DjangoObjectAuthorization(Authorization):
    '''
    Uses permission checking from ``django.contrib.auth`` to map
    ``POST / PUT / DELETE / PATCH`` to their equivalent Django auth
    permissions.

    Both the list & detail simply check the object they're based on.
    Object level authorization api is added since django 1.5. However,
    it will default to no-access unless an AUTHENTICATION_BACKENDS is
    setup to handle those checks.
    '''

    # By default, follows `ModelAdmin` "convention" to use `app.change_model`
    # `django.contrib.auth.models.Permission` for both viewing and updating.
    # https://docs.djangoproject.com/es/1.9/topics/auth/default/#permissions-and-authorization
    READ_PERM_CODE = getattr(settings, 'TASTYPIE_READ_PERM_CODE', 'change')

    def base_checks(self, request, model_klass):
        # If it doesn't look like a model, we can't check permissions.
        if not model_klass or not getattr(model_klass, '_meta', None):
            return False

        # User must be logged in to check permissions.
        if not hasattr(request, 'user'):
            return False

        return model_klass

    def perm_list_checks(self, request, code, obj_list):
        klass = self.base_checks(request, obj_list.model)
        if klass is False:
            raise Unauthorized("You are not allowed to access that resource.")

        permission = '%s.%s_%s' % (
            klass._meta.app_label,
            code,
            get_module_name(klass._meta)
        )

        if request.user.has_perm(permission, obj_list):
            return obj_list

        return obj_list.none()

    def perm_obj_checks(self, request, code, obj):
        klass = self.base_checks(request, obj.__class__)
        if klass is False:
            raise Unauthorized("You are not allowed to access that resource.")

        permission = '%s.%s_%s' % (
            klass._meta.app_label,
            code,
            get_module_name(klass._meta)
        )

        if request.user.has_perm(permission, obj):
            return True

        return False

    def read_list(self, object_list, bundle):
        return self.perm_list_checks(bundle.request, self.READ_PERM_CODE, object_list)

    def read_detail(self, object_list, bundle):
        return self.perm_obj_checks(bundle.request, self.READ_PERM_CODE, bundle.obj)

    def create_list(self, object_list, bundle):
        return self.perm_list_checks(bundle.request, 'add', object_list)

    def create_detail(self, object_list, bundle):
        return self.perm_obj_checks(bundle.request, 'add', bundle.obj)

    def update_list(self, object_list, bundle):
        return self.perm_list_checks(bundle.request, 'change', object_list)

    def update_detail(self, object_list, bundle):
        return self.perm_obj_checks(bundle.request, 'change', bundle.obj)

    def delete_list(self, object_list, bundle):
        return self.perm_list_checks(bundle.request, 'delete', object_list)

    def delete_detail(self, object_list, bundle):
        return self.perm_obj_checks(bundle.request, 'delete', bundle.obj)

