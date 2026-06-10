"""
Management command para executar limpeza de tokens manualmente.

Uso:
    python manage.py cleanup_tokens --type all
    python manage.py cleanup_tokens --type tokens
    python manage.py cleanup_tokens --type refresh
    python manage.py cleanup_tokens --type audit
    python manage.py cleanup_tokens --type all --dry-run
"""

from django.core.management.base import BaseCommand, CommandError

from drf_cas_jwt.tasks import (
    cleanup_expired_tokens,
    cleanup_old_audit_logs,
    cleanup_soft_deleted_tokens,
    cleanup_revoked_refresh_tokens,
)


class Command(BaseCommand):
    help = 'Cleanup expired tokens, refresh tokens, and audit logs'

    def add_arguments(self, parser):
        parser.add_argument(
            '--type',
            type=str,
            default='all',
            choices=['all', 'tokens', 'refresh', 'audit'],
            help='Type of cleanup to perform'
        )

        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )

    def handle(self, *args, **options):
        cleanup_type = options['type']
        dry_run = options['dry_run']

        if dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN: Nenhum registro será deletado')
            )

        try:
            if cleanup_type == 'all':
                result = cleanup_expired_tokens()
                self.display_result(result)

            elif cleanup_type == 'tokens':
                result = cleanup_soft_deleted_tokens()
                self.display_result(result)

            elif cleanup_type == 'refresh':
                result = cleanup_revoked_refresh_tokens()
                self.display_result(result)

            elif cleanup_type == 'audit':
                result = cleanup_old_audit_logs()
                self.display_result(result)

            self.stdout.write(self.style.SUCCESS('✅ Limpeza completa!'))

        except Exception as e:
            raise CommandError(f'Erro na limpeza: {str(e)}')

    def display_result(self, result):
        """Exibir resultados formatados."""
        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('=== Resultado da Limpeza ==='))

        for key, value in result.items():
            if key == 'timestamp':
                self.stdout.write(f'  Timestamp: {value}')
            else:
                self.stdout.write(f'  {key}: {self.style.SUCCESS(str(value))}')

        self.stdout.write('')
