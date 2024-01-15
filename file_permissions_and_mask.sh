# File Permissions and Mask
# Verify Permissions on Important Files and Directories
# Verify Permissions on Files with Local Account Information and Credentials
# Verify Group Who Owns Backup group File
chgrp 0 /etc/group-

# Verify Group Who Owns Backup gshadow File
chgrp 42 /etc/gshadow-

# Verify Group Who Owns Backup passwd File
chgrp 0 /etc/passwd-

# Verify User Who Owns Backup shadow File
chgrp 42 /etc/shadow-

# Verify Group Who Owns group File
chgrp 0 /etc/group

# Verify Group Who Owns gshadow File
chgrp 42 /etc/gshadow

# Verify Group Who Owns passwd File
chgrp 0 /etc/passwd

# Verify Group Who Owns shadow File 
chgrp 42 /etc/shadow

# Verify User Who Owns Backup group File
chown 0 /etc/group-

# Verify User Who Owns Backup gshadow File
chown 0 /etc/gshadow-

# Verify User Who Owns Backup passwd File
chown 0 /etc/passwd-

# Verify Group Who Owns Backup shadow File
chown 0 /etc/shadow-

# Verify User Who Owns group File
chown 0 /etc/group

# Verify User Who Owns gshadow File
chown 0 /etc/gshadow

# Verify User Who Owns passwd File 
chown 0 /etc/passwd

# Verify User Who Owns shadow File
chown 0 /etc/shadow

# Verify Permissions on Backup group File
chmod u-xs,g-xws,o-xwt /etc/group-

# Verify Permissions on Backup gshadow File
chmod u-xs,g-xws,o-xwrt /etc/gshadow-

# Verify Permissions on Backup passwd File
chmod u-xs,g-xws,o-xwt /etc/passwd-