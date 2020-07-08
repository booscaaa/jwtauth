CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE access (
    id serial primary key not null,
    login varchar(15) not null unique,
    password varchar(75) not null,
    email varchar(75) not null
);


CREATE TABLE auth (
    id serial primary key not null,
    access_id integer not null,
    token varchar not null,
    refresh varchar(75) not null,
    type varchar(20) not null,
    is_revoked boolean not null default false,

    CONSTRAINT access_id_fk
	FOREIGN KEY (access_id) REFERENCES access (id)
);