import streamlit as st
import pandas as pd
import string
import random
import base64
from datetime import datetime
import io
from collections import defaultdict

class PasswordManager:
    def __init__(self):
        if 'passwords' not in st.session_state:
            st.session_state.passwords = pd.DataFrame(
                columns=['site', 'username', 'password', 'date_added', 'last_modified']
            )
        if 'show_passwords' not in st.session_state:
            st.session_state.show_passwords = False

    def generate_password(self, length=12):
        characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*"
        while True:
            password = ''.join(random.choice(characters) for _ in range(length))
            if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in "!@#$%^&*" for c in password)):
                return password

    def validate_password(self, password):
        checks = {
            'length': len(password) >= 8,
            'lowercase': any(c.islower() for c in password),
            'uppercase': any(c.isupper() for c in password),
            'digits': any(c.isdigit() for c in password),
            'special': any(c in string.punctuation for c in password)
        }
        return checks

    def get_password_strength(self, password):
        checks = self.validate_password(password)
        strength = (sum(checks.values()) / len(checks)) * 100
        return strength

    def find_duplicate_passwords(self):
        """Find accounts using the same password"""
        if len(st.session_state.passwords) == 0:
            return {}
        
        password_groups = defaultdict(list)
        for _, row in st.session_state.passwords.iterrows():
            password_groups[row['password']].append({
                'site': row['site'],
                'username': row['username']
            })
        
        # Filter out passwords that are not duplicated
        return {k: v for k, v in password_groups.items() if len(v) > 1}

def main():
    st.set_page_config(
        page_title="Secure Password Manager",
        page_icon="🔒",
        layout="wide"
    )

    # Initialize password manager
    pm = PasswordManager()

    # Sidebar for actions
    with st.sidebar:
        st.header("Actions")
        action = st.radio(
            "Choose an action:",
            ["View Passwords", "Add New Password", "Import/Export", "Security Analysis"]  # Added new option
        )

    if action == "Security Analysis":
        st.header("🔍 Security Analysis")
        
        # Find duplicate passwords
        duplicates = pm.find_duplicate_passwords()
        
        if duplicates:
            st.warning("⚠️ Duplicate Passwords Detected!", icon="⚠️")
            st.markdown("The following accounts are using the same passwords:")
            
            for password, accounts in duplicates.items():
                with st.expander(f"Password used by {len(accounts)} accounts"):
                    # Create a nice table for each group of accounts
                    accounts_df = pd.DataFrame(accounts)
                    st.dataframe(
                        accounts_df,
                        hide_index=True,
                        column_config={
                            "site": "Website/Application",
                            "username": "Username/Email"
                        }
                    )
                    st.markdown("**Recommendation:** Consider changing these passwords to unique ones for better security.")
            
            # Add a button to generate new unique passwords
            if st.button("Generate New Unique Passwords"):
                new_passwords = {}
                for password in duplicates.keys():
                    for account in duplicates[password]:
                        new_passwords[(account['site'], account['username'])] = pm.generate_password()
                
                # Display the suggested new passwords
                st.markdown("### Suggested New Passwords")
                for (site, username), new_password in new_passwords.items():
                    st.code(f"{site} ({username}): {new_password}")
                st.info("Copy these passwords and update them in your accounts for better security.")
        else:
            st.success("✅ No duplicate passwords found! Good job keeping your accounts secure.")
        
        # Additional security statistics
        if len(st.session_state.passwords) > 0:
            st.markdown("### Password Strength Analysis")
            
            # Calculate average password strength
            strengths = [pm.get_password_strength(p) for p in st.session_state.passwords['password']]
            avg_strength = sum(strengths) / len(strengths)
            
            # Display average strength with color coding
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Average Password Strength", f"{avg_strength:.1f}%")
            with col2:
                strength_color = "red" if avg_strength < 60 else "yellow" if avg_strength < 80 else "green"
                st.markdown(f"Status: <span style='color: {strength_color};'>{'Weak' if avg_strength < 60 else 'Medium' if avg_strength < 80 else 'Strong'}</span>", unsafe_allow_html=True)
            
            # Password length distribution
            st.markdown("### Password Length Distribution")
            lengths = [len(p) for p in st.session_state.passwords['password']]
            length_df = pd.DataFrame({'Length': lengths})
            st.bar_chart(length_df['Length'].value_counts())

    elif action == "View Passwords":
        st.header("Stored Passwords")
        
        search = st.text_input("🔍 Search passwords", placeholder="Search by website or username")
        
        show_all = st.checkbox("Show All Passwords")
        
        if len(st.session_state.passwords) > 0:
            df_display = st.session_state.passwords.copy()
            if search:
                mask = (df_display['site'].str.contains(search, case=False)) | \
                       (df_display['username'].str.contains(search, case=False))
                df_display = df_display[mask]
            
            if not show_all:
                df_display['password'] = '••••••••'
            
            if 'date_added' in df_display.columns:
                df_display['date_added'] = pd.to_datetime(df_display['date_added']).dt.strftime('%Y-%m-%d %H:%M')
            if 'last_modified' in df_display.columns:
                df_display['last_modified'] = pd.to_datetime(df_display['last_modified']).dt.strftime('%Y-%m-%d %H:%M')
            
            st.dataframe(
                df_display,
                hide_index=True,
                column_config={
                    "site": "Website/Application",
                    "username": "Username/Email",
                    "password": "Password",
                    "date_added": "Date Added",
                    "last_modified": "Last Modified"
                }
            )
        else:
            st.info("No passwords stored yet. Add some passwords to see them here!")

    elif action == "Add New Password":
        st.header("Add New Password")
        
        col1, col2 = st.columns(2)
        
        with col1:
            site = st.text_input("Website/Application", placeholder="Enter website name")
            username = st.text_input("Username/Email", placeholder="Enter username or email")
            password = st.text_input(
                "Password",
                type="password" if not st.session_state.show_passwords else "text",
                placeholder="Enter password or generate one"
            )
            
            show_password = st.checkbox("Show Password", value=st.session_state.show_passwords)
            st.session_state.show_passwords = show_password

            if st.button("Generate Strong Password"):
                password = pm.generate_password()
                st.code(password)

        with col2:
            if password:
                strength = pm.get_password_strength(password)
                st.markdown("### Password Strength")
                color = "red" if strength < 40 else "yellow" if strength < 70 else "green"
                st.progress(strength/100)
                st.markdown(f"<p style='color: {color};'>Strength: {strength:.0f}%</p>", 
                          unsafe_allow_html=True)
                
                checks = pm.validate_password(password)
                st.markdown("### Requirements")
                for requirement, passed in checks.items():
                    icon = "✅" if passed else "❌"
                    st.markdown(f"{icon} {requirement.title()}")

        if st.button("Add Password", type="primary"):
            if not all([site, username, password]):
                st.error("All fields are required!")
            else:
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                new_entry = pd.DataFrame({
                    'site': [site],
                    'username': [username],
                    'password': [password],
                    'date_added': [current_time],
                    'last_modified': [current_time]
                })
                st.session_state.passwords = pd.concat(
                    [st.session_state.passwords, new_entry],
                    ignore_index=True
                )
                st.success("Password added successfully!")
                st.balloons()

    else:  # Import/Export
        st.header("Import/Export Passwords")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Import Passwords")
            uploaded_file = st.file_uploader("Upload CSV file", type="csv")
            
            if uploaded_file is not None:
                try:
                    df = pd.read_csv(uploaded_file)
                    required_columns = ['site', 'username', 'password']
                    
                    if not all(col in df.columns for col in required_columns):
                        st.error("CSV must contain site, username, and password columns")
                    else:
                        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        if 'date_added' not in df.columns:
                            df['date_added'] = current_time
                        if 'last_modified' not in df.columns:
                            df['last_modified'] = current_time
                            
                        st.session_state.passwords = pd.concat(
                            [st.session_state.passwords, df],
                            ignore_index=True
                        ).drop_duplicates(['site', 'username'])
                        st.success("Passwords imported successfully!")
                except Exception as e:
                    st.error(f"Error importing passwords: {str(e)}")
        
        with col2:
            st.subheader("Export Passwords")
            if len(st.session_state.passwords) > 0:
                csv = st.session_state.passwords.to_csv(index=False)
                b64 = base64.b64encode(csv.encode()).decode()
                
                st.download_button(
                    label="Download Passwords as CSV",
                    data=csv,
                    file_name="passwords.csv",
                    mime="text/csv",
                )
            else:
                st.info("No passwords to export!")

if __name__ == "__main__":
    main()