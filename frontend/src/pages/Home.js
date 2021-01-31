import React from 'react';
import PostFeed from './PostFeed';

function Home(props) {
  return (
    <>
      <h2>Welcome to BearChat!</h2>
      <small>Your secure home for your social media presence.</small>
      <hr />
      <PostFeed />
    </>
  );
}

export default Home;
