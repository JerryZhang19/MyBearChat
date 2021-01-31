import React from 'react';
import { Switch, Route } from 'react-router-dom';
import './App.css';
import Layout from './common/Layout/Layout';

import Home from './pages/Home';
import Signup from './pages/Signup';
import Signin from './pages/Signin';
import LogOut from './pages/LogOut';
import Profile from './pages/Profile';

function App() {
  return (
    <Layout>
      <Switch>
        <Route exact path='/' component={Home}></Route>
        <Route exact path='/signup' component={Signup}></Route>
        <Route exact path='/signin' component={Signin}></Route>
        <Route exact path='/logout' component={LogOut}></Route>
        <Route path='/profile/:uuid?' component={Profile}></Route>
      </Switch>
    </Layout>
  );
}

export default App;
