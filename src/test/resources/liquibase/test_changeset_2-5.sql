--liquibase formatted sql

--changeset eze:2
INSERT INTO ROLES VALUES ('admin');
INSERT INTO ROLES VALUES ('user');
INSERT INTO ROLES VALUES ('other');
--rollback TRUNCATE TABLE ROLES AND COMMIT;

--changeset eze:3
insert into roles_permissions values ('admin', 'super');
insert into roles_permissions values ('user', 'bar');
insert into roles_permissions values ('admin', 'foo');
insert into roles_permissions values ('other', 'gee');
--rollback TRUNCATE TABLE roles_permissions AND COMMIT;

--changeset eze:4
INSERT INTO USERS ( USER_ID, USERNAME , PASSWORD ) VALUES (101, 'TEST', 'PASSWORD');
INSERT INTO USERS ( USER_ID, USERNAME , PASSWORD ) VALUES (102, 'Arnold', '12345678');
INSERT INTO USERS ( USERNAME , PASSWORD ) VALUES ('EXISTS', '12345678');
--rollback TRUNCATE TABLE USERS RESTART IDENTITY AND COMMIT;

--changeset eze:5
insert into users_roles values (101, 'admin');
insert into users_roles values (101, 'user');
insert into users_roles values (102, 'user');
--rollback TRUNCATE TABLE users_roles AND COMMIT;
