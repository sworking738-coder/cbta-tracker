# CBTA Progress Tracker

Web app untuk mencatat progres CBTA (form BT-RRF-079/R0, 68 tugas OJT, 11 kompetensi) bagi mekanik pesawat.

- **Assessor**: login email, mencatat penilaian per tugas lengkap dengan observable behaviour.
- **Pembina**: login email, melihat dashboard dan detail tiap mekanik (baca saja).
- **Admin**: menyetujui akun baru dan memberi peran (tab Pengguna). Akun pertama yang mendaftar otomatis menjadi admin.
- **Mekanik**: tanpa login, cukup ketik no. pegawai untuk melihat kartu status dan progres sendiri.

Satu file statis (`index.html`) dengan backend Supabase (project `cbta-tracker`, region Singapura). Hak akses dijaga oleh Row Level Security di database.
