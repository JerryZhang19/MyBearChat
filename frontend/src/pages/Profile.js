import React, { useState }  from 'react';
import { Button, Form, Card, InputGroup, FormControl } from 'react-bootstrap';
import { request, getUUID, HOST } from '../common/utils.js';
import swal from 'sweetalert';

import { useParams } from "react-router-dom";

function Profile(props) {

  let { uuid } = useParams();

  const ourUUID = getUUID();

  console.log("Requested profile ID:", uuid);
  console.log("Our uuid:", ourUUID);

  const [profile, setProfile] = useState(null);

  if (profile === null) {
    request('GET', `http://${HOST}:82/api/profile/${ourUUID}`, {})
        .then((res) => {
          // console.log(res.responseText);
          setProfile(JSON.parse(res.responseText));
        })
        .catch(() => {
          console.error("Could not retrieve profile!");
        })
    ;
  }

  const send = (e) => {
    e.preventDefault();

    const content = {
      "firstName": e.target[0].value,
      "lastName": e.target[1].value,
      "uuid": ourUUID,
      "email": e.target[2].value
    };

    console.log("Profile formContent:", content);

    request('PUT', `http://${HOST}:82/api/profile/${ourUUID}`, {}, JSON.stringify(content))
      .then((res) => {
        console.log(res.status);
        swal({
          title: "Updated!",
          text: "Successfully updated profile!",
          icon: "success",
          timeout: 5000
        }).then(() => {
          window.location.reload();
        });
      })
      .catch((res) => {
        console.log("err: ", res);
        const errMessage = res?.responseText?.trim();
        swal({
          title: "Could not update profile!",
          text: `Error when attempting to update profile (HTTP ${res.status}): ${errMessage}.`,
          icon: "error"
        });
      });
  };

  const thisIsUs = !uuid || ourUUID === uuid; // if we are looking at ourselves or not

  var profileHtml = [];
  if (profile) {
    profileHtml = (
      <Card style={{ width: '35rem' }}>
        <Card.Body>
          <Card.Title>{profile.firstName} {profile.lastName}</Card.Title>
          <Card.Subtitle className="mb-2 text-muted">User ID {profile.uuid}</Card.Subtitle>
          <Card.Text>Email {profile.firstName} at <a href={`mailto:${profile.email}`}>{profile.email}</a>.</Card.Text>
        </Card.Body>
      </Card>
    );
  } else {
    if (thisIsUs) {
      profileHtml = (<p>You have not created a profile yet.</p>);
    } else {
      profileHtml = (<p>This user has not created a profile yet.</p>);
    }
  }

  var friendsHtml = "Loading...";

  const [friends, setFriends] = useState(null);

  if (!thisIsUs) {
    if (friends !== null) {
      if (friends === false) {
        friendsHtml = "Error retrieving friends list.";
      } else {
        const areFriends = friends.includes(uuid);
        if (areFriends) {
          friendsHtml = "You are friends with ";
        } else {
          friendsHtml = "You are not friends with ";
        }
        const personName = profile?.firstName ?? "this person";
        friendsHtml += personName;
        friendsHtml += ".";

        friendsHtml = (<p>{friendsHtml}</p>);

        if (!areFriends) {
          const addFriend = (e) => {
            e.preventDefault();
            request('POST', `http://${HOST}:83/api/friends/${uuid}`, {}, "")
              .then((res) => {
                console.log(res.status);
                swal({
                  title: "Added Friend!",
                  text: `Successfully added ${personName} as a friend!`,
                  icon: "success",
                  timeout: 5000
                }).then(() => {
                  window.location.reload();
                });
              })
              .catch((res) => {
                console.log("err: ", res);
                swal({
                  title: "Could not add friend!",
                  text: `Error when attempting to add friend (HTTP Status ${res.status}): ${res?.responseText?.trim()}.`,
                  icon: "error"
                });
              });
          };

          friendsHtml = (<>
            {friendsHtml}
            <Button onClick={addFriend} variant="primary">Add as Friend!</Button>
          </>)
        }
      }
    } else {
      request('GET', `http://${HOST}:83/api/friends`, {})
          .then((res) => {
            setFriends(JSON.parse(res.responseText));
          })
          .catch(() => {
            setFriends(false);
            console.error("Could not retrieve friends!");
          })
      ;
    }
  }

  return (
    <>
      {thisIsUs ? (<>
        <h3>Update Your Profile</h3>
        <Form onSubmit={ send }>
          <Form.Group controlId="formContent">
            <InputGroup className="mb-3">
              <InputGroup.Prepend>
                <InputGroup.Text>First and last name</InputGroup.Text>
              </InputGroup.Prepend>
              <FormControl name="firstName" placeholder={profile?.firstName ?? "Oski"} />
              <FormControl name="lastName" placeholder={profile?.lastName ?? "Bear"} />
            </InputGroup>

            <InputGroup className="mb-3">
              <FormControl
                placeholder={profile?.email ?? "oski@berkeley.edu"}
                name="email"
                type="email"
              />
            </InputGroup>
          </Form.Group>
          <Button variant="primary" type="submit">
            Update!
          </Button>
        </Form>

        <hr />

        <h3>Your Profile</h3>
        { profileHtml}
      </>) : (<>
        <h3>Profile</h3>
        { profileHtml }

        <hr />

        <h3>Friends</h3>
        { friendsHtml }
      </>)}
    </>
  );
}

export default Profile;
