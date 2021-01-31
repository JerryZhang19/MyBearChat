import React, { useState }  from 'react';
import './Layout.css';
import Navbar from './Navbar';

function Layout(props) {
  return (
    <>
      <Navbar />
      <div className="container">
      { props.children }
      </div>
    </>
  );
}

export default Layout;
