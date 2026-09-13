CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(200) NOT NULL,
    password_hash TEXT NOT NULL,

    role VARCHAR(20) NOT NULL
        CHECK (role IN ('admin', 'teacher')),

    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'inactive')),

    is_hod BOOLEAN NOT NULL DEFAULT FALSE,
    is_exam_officer BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS classes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    level VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subjects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(150) UNIQUE NOT NULL,
    code VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS teacher_subjects (
    teacher_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject_id UUID NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    PRIMARY KEY (teacher_id, subject_id)
);

CREATE TABLE IF NOT EXISTS teacher_classes (
    teacher_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    PRIMARY KEY (teacher_id, class_id)
);

CREATE TABLE IF NOT EXISTS hod_subjects (
    teacher_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject_id UUID NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    PRIMARY KEY (teacher_id, subject_id)
);

CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    teacher_id UUID NOT NULL REFERENCES users(id),

    document_type VARCHAR(30) NOT NULL
        CHECK (
            document_type IN
            ('Scheme of Work', 'Lesson Plan', 'Lesson Note')
        ),

    title VARCHAR(300) NOT NULL,

    subject VARCHAR(150),
    class_name VARCHAR(100),
    session VARCHAR(50),
    term VARCHAR(50),
    week VARCHAR(50),

    content JSONB NOT NULL DEFAULT '{}'::jsonb,

    status VARCHAR(30) NOT NULL DEFAULT 'Draft'
        CHECK (
            status IN
            ('Draft', 'Submitted', 'HOD Approved', 'Rejected')
        ),

    submitted_at TIMESTAMP,
    approved_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    teacher_id UUID NOT NULL REFERENCES users(id),

    assessment_type VARCHAR(30) NOT NULL
        CHECK (assessment_type IN ('CA', 'Examination')),

    title VARCHAR(300) NOT NULL,

    subject VARCHAR(150),
    class_name VARCHAR(100),
    session VARCHAR(50),
    term VARCHAR(50),

    instructions TEXT,

    objective_questions JSONB NOT NULL DEFAULT '[]'::jsonb,
    theory_questions JSONB NOT NULL DEFAULT '[]'::jsonb,
    marking_scheme JSONB NOT NULL DEFAULT '[]'::jsonb,

    status VARCHAR(40) NOT NULL DEFAULT 'Draft'
        CHECK (
            status IN (
                'Draft',
                'Submitted',
                'HOD Approved',
                'HOD Rejected',
                'Finalized'
            )
        ),

    submitted_at TIMESTAMP,
    hod_approved_at TIMESTAMP,
    exam_approved_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    item_id UUID NOT NULL,
    item_type VARCHAR(30) NOT NULL,

    approver_id UUID NOT NULL REFERENCES users(id),

    decision VARCHAR(30) NOT NULL
        CHECK (
            decision IN
            ('Approved', 'Rejected', 'Finalized')
        ),

    comment TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS approved_archive (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    source_id UUID NOT NULL,
    source_type VARCHAR(30) NOT NULL,

    title VARCHAR(300) NOT NULL,

    teacher_id UUID REFERENCES users(id),

    teacher_name VARCHAR(200),

    subject VARCHAR(150),
    class_name VARCHAR(100),
    session VARCHAR(50),
    term VARCHAR(50),

    content JSONB NOT NULL DEFAULT '{}'::jsonb,

    marking_scheme JSONB NOT NULL DEFAULT '[]'::jsonb,

    approved_by_hod UUID REFERENCES users(id),
    approved_by_exam_officer UUID REFERENCES users(id),

    approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(source_id, source_type)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID REFERENCES users(id),

    action VARCHAR(200) NOT NULL,

    entity_type VARCHAR(100),
    entity_id UUID,

    details JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS school_settings (
    id INTEGER PRIMARY KEY DEFAULT 1,

    school_name VARCHAR(300)
        DEFAULT 'Caliphate Tarbiya Academy',

    address TEXT,

    phone VARCHAR(100),

    email VARCHAR(200),

    logo_url TEXT,

    motto VARCHAR(300),

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO school_settings
(id, school_name)
VALUES
(1, 'Caliphate Tarbiya Academy')
ON CONFLICT (id) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_documents_teacher
ON documents(teacher_id);

CREATE INDEX IF NOT EXISTS idx_documents_status
ON documents(status);

CREATE INDEX IF NOT EXISTS idx_assessments_teacher
ON assessments(teacher_id);

CREATE INDEX IF NOT EXISTS idx_assessments_status
ON assessments(status);

CREATE INDEX IF NOT EXISTS idx_archive_subject
ON approved_archive(subject);

CREATE INDEX IF NOT EXISTS idx_archive_class
ON approved_archive(class_name);

CREATE INDEX IF NOT EXISTS idx_archive_session
ON approved_archive(session);

CREATE INDEX IF NOT EXISTS idx_audit_user
ON audit_logs(user_id);
