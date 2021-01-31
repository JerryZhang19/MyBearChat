import React, { useState }  from 'react';
import { Button, Form } from 'react-bootstrap';
import { request, HOST } from '../common/utils.js';
import swal from 'sweetalert';

function Signin(props) {

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('' );

  const send = (e) => {
    e.preventDefault();
    request('POST', `http://${HOST}:80/api/auth/signin`, {}, JSON.stringify({ username, password }))
      .then((res) => {
        console.log(res.status);
        swal({
          title: "Signed in!",
          text: "You've successfully logged in!",
          icon: "success",
          timeout: 5000
        }).then(() => {
          window.location.href = '/';
        });
      })
      .catch((res) => {
        console.log("err: ", res);
        swal({
          title: "Could not sign in!",
          text: `Error when attempting to sign in (HTTP ${res.status}): ${res?.responseText?.trim()}.`,
          icon: "error"
        });
      });
  }

  return (
    <>
      <Form onSubmit={ send }>
        <Form.Group controlId="formUsername">
          <Form.Label>Username</Form.Label>
          <Form.Control
            type="text"
            name="username"
            placeholder="Username"
            onChange={(e) => setUsername(e.target.value)}
          />
        </Form.Group>
        <Form.Group controlId="formPassword">
          <Form.Label>Password</Form.Label>
          <Form.Control
            type="password"
            name="password"
            placeholder="Password"
            onChange={(e) => setPassword(e.target.value)}
          />
        </Form.Group>
        <Button variant="primary" type="submit">
          Sign In
        </Button>
      </Form>
    </>
  );
}

export default Signin;
