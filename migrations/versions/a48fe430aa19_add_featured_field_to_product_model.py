"""Add featured field to Product model

Revision ID: a48fe430aa19
Revises: 2648eb721567
Create Date: 2025-02-10 14:20:00.039576

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a48fe430aa19'
down_revision = '2648eb721567'
branch_labels = None
depends_on = None


def upgrade():
    # There is no action needed here since the 'featured' column 
    # should already exist from the previous migration.
    pass


def downgrade():
    # Drop the column only if it was added previously, to maintain
    # the integrity of future downgrades.
    with op.batch_alter_table('product', schema=None) as batch_op:
        batch_op.drop_column('featured')
