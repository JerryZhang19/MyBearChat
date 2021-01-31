import React, { useState }  from 'react';
import { Button, Form, Card } from 'react-bootstrap';
import { request, HOST } from '../common/utils.js';
import swal from 'sweetalert';

function PostFeed(props) {

  const [posts, setPosts] = useState(null);

  if (posts === null) {
    request('GET', `http://${HOST}:81/api/posts/0`, {})
        .then((res) => {
          // console.log(res.responseText);
          setPosts(JSON.parse(res.responseText));
        })
        .catch(() => {
          console.error("Could not retrieve posts!");
        })
    ;
  }

  const [content, setContent] = useState('');

  const send = (e) => {
    e.preventDefault();
    request('POST', `http://${HOST}:81/api/posts/create`, {}, JSON.stringify({ content }))
      .then((res) => {
        console.log(res.status);
        swal({
          title: "Posted!",
          text: "Successfully created post!",
          icon: "success",
          timeout: 5000
        }).then(() => {
          window.location.href = '/';
        });
      })
      .catch((res) => {
        console.log("err: ", res);
        swal({
          title: "Could not create post!",
          text: `Error when attempting to create post (HTTP ${res.status}): ${res.responseText.trim()}.`,
          icon: "error"
        });
      });
  };

  var postsHtml = [];
  if (posts && posts.length) {
    var idx = 0;
    for (var post of posts) {
      idx += 1;
      postsHtml.push(
        <Card style={{ width: '35rem' }} key={idx}>
          <Card.Body>
            <Card.Title><a href={`/profile/${post.authorID}`}>User ID {post.authorID}</a></Card.Title>
            <Card.Subtitle className="mb-2 text-muted">Posted at {post.postTime}</Card.Subtitle>
            <Card.Text>{post.content}</Card.Text>
          </Card.Body>
        </Card>
      );
      // postsHtml.push(`${post.authorID}: ${post.content} <br />`);
    }
  } else {
    postsHtml = (<p>No posts in your feed from others.</p>);
  }

  var friendsHtml = "Loading...";
  const [friends, setFriends] = useState(null);

  if (friends === null) {
    request('GET', `http://${HOST}:83/api/friends`, {})
        .then((res) => {
          setFriends(JSON.parse(res.responseText));
        })
        .catch(() => {
          setFriends(false);
          console.error("Could not retrieve friends!");
        })
    ;
  } else {
    if (friends === false) {
      friendsHtml = "Error retrieving friends list.";
    } else {
      friendsHtml = [];
      for (var uuid of friends) {
        friendsHtml.push(<p><a href={`/profile/${uuid}`}>User ID {uuid}</a></p>);
      }

      if (!friends.length) {
        friendsHtml = (<p>You have not added anyone as your friend. Go add someone!</p>);
      }
    }
  }

  return (
    <>
      <h3>New Post</h3>
      <Form onSubmit={ send }>
        <Form.Group controlId="formContent">
          <Form.Control
            as="textarea"
            name="content"
            placeholder="Share your thoughts..."
            onChange={(e) => setContent(e.target.value)}
          />
        </Form.Group>
        <Button variant="primary" type="submit">
          Post!
        </Button>
      </Form>

      <hr />
      <h3>Your Feed</h3>
      { postsHtml }

      <hr />
      <h3>Your Friends</h3>
      { friendsHtml }
    </>
  );
}

export default PostFeed;
