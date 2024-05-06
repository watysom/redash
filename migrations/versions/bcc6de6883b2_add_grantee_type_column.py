"""Add grantee_type column

Revision ID: bcc6de6883b2
Revises: 7205816877ec
Create Date: 2024-05-04 17:08:04.613051

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bcc6de6883b2'
down_revision = '7205816877ec'
branch_labels = None
depends_on = None

table_name = "access_permissions"
column_name = "grantee_type"


def upgrade():
    op.add_column(table_name, sa.Column(column_name, sa.String(255), nullable=True))
    op.execute(f"UPDATE {table_name} SET {column_name} = 'users'")
    op.alter_column(table_name, column_name, nullable=False)


def downgrade():
    op.drop_column(table_name, column_name)
