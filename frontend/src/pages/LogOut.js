import React, { useState }  from 'react';
import { request, HOST } from '../common/utils.js';

function LogOut(props) {

  const [out, setOut] = useState(null);

  if (out === null) {
    request('POST', `http://${HOST}:80/api/auth/logout`, {})
        .then((res) => {
          console.log(res.responseText);
          setOut(true);
        })
        .catch(() => {
          console.error("Could not log out!");
          setOut(false);
        })
    ;

    return (<h4>Logging out...</h4>);
  } else if (out === true) {
    return (<h4>Logged Out!</h4>);
  } else {
    return (<h4>Failed to log out.</h4>);
  }
}

export default LogOut;
