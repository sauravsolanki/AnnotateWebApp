"""empty message

Revision ID: e14cf0442cbd
Revises: 
Create Date: 2019-01-03 00:35:01.677384

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e14cf0442cbd'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('imagelinks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('links', sa.String(length=120), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('info',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('aid', sa.String(length=64), nullable=True),
    sa.Column('uid', sa.String(length=64), nullable=True),
    sa.Column('imagelinks', sa.String(length=120), nullable=True),
    sa.Column('dateOfAnnotation', sa.String(length=100), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('puids',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('puid', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('ruids',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ruid', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('uids',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uid', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('uid')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=64), nullable=True),
    sa.Column('username', sa.String(length=64), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    op.drop_table('uids')
    op.drop_table('ruids')
    op.drop_table('puids')
    op.drop_table('info')
    op.drop_table('imagelinks')
    # ### end Alembic commands ###