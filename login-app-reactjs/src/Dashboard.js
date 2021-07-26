import React from 'react';

function Dashboard(props) {

  // handle click event of logout button
  const handleLogout = () => {
//    removeUserSession();
    props.history.push('/login');
  }

  return (
    <div>
      Welcome!<br /><br />
      <input type="button" onClick={handleLogout} value="Logout" />
    </div>
  );
}

export default Dashboard;
