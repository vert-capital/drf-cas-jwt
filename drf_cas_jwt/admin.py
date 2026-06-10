from django.contrib import admin

from .models import Token, TokenAuditLog, RefreshTokenFamily, SecurityAlertRecipient


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ["id", "user", "ip", "jti", "created_at", "deleted_at"]
    list_display_links = ["id"]
    list_filter = ["deleted_at"]
    search_fields = ["user__email", "ip", "jti"]
    ordering = ["-created_at"]
    readonly_fields = ["id", "user", "ip", "jti", "token", "created_at", "updated_at", "deleted_at"]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(RefreshTokenFamily)
class RefreshTokenFamilyAdmin(admin.ModelAdmin):
    list_display = ["jti", "user", "ip", "parent_jti", "created_at", "rotated_at", "revoked_at"]
    list_display_links = ["jti"]
    list_filter = ["revoked_at", "rotated_at"]
    search_fields = ["user__email", "jti", "parent_jti", "ip"]
    ordering = ["-created_at"]
    readonly_fields = ["jti", "user", "ip", "parent_jti", "created_at", "rotated_at", "revoked_at"]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(TokenAuditLog)
class TokenAuditLogAdmin(admin.ModelAdmin):
    list_display = ["id", "user", "event", "reason", "ip", "created_at"]
    list_display_links = ["id"]
    list_filter = ["event", "reason", "created_at"]
    search_fields = ["user__email", "ip", "user_agent"]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    readonly_fields = ["id", "user", "event", "reason", "ip", "user_agent", "created_at"]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(SecurityAlertRecipient)
class SecurityAlertRecipientAdmin(admin.ModelAdmin):
    list_display = [
        "email", "user", "is_active",
        "notify_on_reuse", "notify_on_rate_limit", "notify_on_login", "created_at",
    ]
    list_display_links = ["email"]
    list_filter = ["is_active", "notify_on_reuse", "notify_on_rate_limit", "notify_on_login"]
    search_fields = ["email", "user__email"]
    ordering = ["email"]
    fields = [
        "user", "email", "is_active",
        "notify_on_reuse", "notify_on_rate_limit", "notify_on_login",
    ]
