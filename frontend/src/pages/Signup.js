import React, { useState } from 'react';
import { Button, Form } from 'react-bootstrap';
import { request, HOST } from '../common/utils.js';
import swal from 'sweetalert';

function Signup(props) {

  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('' );

  const send = (e) => {
    e.preventDefault();
    console.log(email, username);
    request('POST', `http://${HOST}:80/api/auth/signup`, {}, JSON.stringify({ email: email, username: username, password: password }))
      .then((res) => {
        console.log(res.status);
        request('POST', `http://${HOST}:83/api/friends`, {}, "")
          .then((res) => {
            console.log(res.status);
          })
          .catch((res) => {
            console.log("friend err: ", res);
          });
        swal({
          title: "Signed up!",
          text: "You've successfully signed up. Go ahead and log in!",
          icon: "success"
        }).then(() => {
          window.location.href = '/signin';
        });
      })
      .catch((res) => {
        console.log("err: ", res);
        swal({
          title: "Could not sign up!",
          text: `Error when attempting to sign up (HTTP ${res.status}): ${res?.responseText?.trim()}.`,
          icon: "error"
        });
      });
  };

  return (
    <>
      <Form onSubmit={ send }>
        <Form.Group controlId="formBasicEmail">
          <Form.Label>Email</Form.Label>
          <Form.Control
            type="email"
            name="email"
            placeholder="Enter email"
            onChange={(e) => setEmail(e.target.value)}
          />
          <Form.Text className="text-muted small">
            We'll never share your email with anyone else.
          </Form.Text>
        </Form.Group>
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
          Sign Up
        </Button>
      </Form>
    </>
  );
}

export default Signup;
